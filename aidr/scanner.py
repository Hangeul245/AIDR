"""폴더 검사기: 폴더 순회 → 형식 식별 → SHA-256 → 악성 해시 비교 → YARA → 판정."""
from datetime import datetime, timezone
from pathlib import Path

import yara

from aidr import hashes
from aidr.filetype import extension_mismatch, identify
from aidr.grades import ORDER
from aidr.yara_scan import match_file


def scan_file(path: Path, bad_hashes: set[str], rules=None) -> dict:
    """파일 하나를 검사한다. 파일은 읽기만 하고 절대 실행하지 않는다."""
    result = {
        "path": str(path),
        "size": None,
        "sha256": None,
        "file_type": None,
        "verdict": None,
        "reasons": [],      # 판정 근거 (강한 근거)
        "signals": [],      # 약한 신호 (혼자서는 판정 안 바꿈)
    }
    try:
        result["size"] = path.stat().st_size
        result["file_type"] = identify(path)
        result["sha256"] = hashes.sha256_file(path)
    except OSError as e:
        # 읽지 못한 파일은 절대 정상이 아니다
        result["verdict"] = "검토 필요"
        result["reasons"].append(f"읽기 실패: {type(e).__name__}")
        return result

    if extension_mismatch(path, result["file_type"]):
        result["signals"].append("확장자 위장 의심 (실행 파일인데 문서·이미지 확장자)")

    if result["sha256"] in bad_hashes:
        result["verdict"] = "악성"
        result["reasons"].append("악성 해시 목록과 일치")
        return result  # 확정 근거가 있으면 YARA는 건너뛴다

    result["verdict"] = "정상"
    if rules is not None:
        _apply_yara(result, path, rules)
    return result


def _apply_yara(result: dict, path: Path, rules) -> None:
    """YARA 결과를 반영한다. high는 판정 근거, low는 약한 신호, 실패는 검토 필요."""
    try:
        hits = match_file(rules, path)
    except yara.Error as e:  # 시간 초과(TimeoutError)도 여기에 포함된다
        result["verdict"] = "검토 필요"
        result["reasons"].append(f"YARA 검사 실패: {type(e).__name__}")
        return
    for name, severity in hits:
        if severity == "high":
            result["verdict"] = "악성"
            result["reasons"].append(f"YARA 규칙 일치: {name} (high)")
        else:
            result["signals"].append(f"YARA 규칙 일치: {name} ({severity})")


def scan_folder(root: Path, bad_hashes: set[str], rules=None) -> dict:
    """폴더 아래 모든 파일을 검사하고 요약과 함께 돌려준다. 바로가기(심볼릭 링크)는 따라가지 않는다."""
    root = Path(root)
    results = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        results.append(scan_file(path, bad_hashes, rules))

    summary = {grade: 0 for grade in ORDER}
    for r in results:
        summary[r["verdict"]] += 1

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "total": len(results),
        "summary": summary,
        "results": results,
    }