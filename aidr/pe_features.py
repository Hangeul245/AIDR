"""PE 파일에서 EMBER2024(특징 버전 3)와 같은 형식의 특징을 뽑는다.

- 학습 데이터와 특징이 똑같아야 3주차 모델이 우리 파일을 채점할 수 있으므로 공식 추출기(thrember)를 그대로 쓴다
- 파일은 읽기만 하고 절대 실행하지 않는다
- 문자열 특징은 원문이 아니라 개수·분포만 남으므로 사용자 파일 내용이 결과에 남지 않는다
"""
import json
from pathlib import Path

from aidr.filetype import identify

# 파일을 통째로 읽으므로 상한을 둔다 (4주차 크기 제한 때 다시 정함)
MAX_BYTES = 64 * 1024 * 1024
PATTERNS = ("*.exe", "*.dll")

_extractor = None


class FeatureError(Exception):
    pass


def _get_extractor():
    global _extractor
    if _extractor is None:
        import thrember  # 무거워서 실제로 쓸 때만 불러온다
        _extractor = thrember.PEFeatureExtractor()
    return _extractor


def extract_file(path):
    """PE 파일 하나의 raw 특징(dict). 실패하면 FeatureError."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_BYTES:
            raise FeatureError(f"크기 초과 ({size}바이트)")
        bytez = path.read_bytes()
    except OSError as e:
        raise FeatureError(f"읽기 실패: {type(e).__name__}") from None
    try:
        return _get_extractor().raw_features(bytez)
    except Exception as e:  # 외부 파서가 망가진 파일에서 어떤 예외를 낼지 모름
        raise FeatureError(f"추출 실패: {type(e).__name__}") from None


def extract_folder(root, out_path, limit=None, label=None):
    """폴더 바로 아래의 exe·dll에서 특징을 뽑아 JSONL(한 줄 = 파일 하나)로 저장한다."""
    root, out_path = Path(root), Path(out_path)
    files = sorted({p for pat in PATTERNS for p in root.glob(pat) if p.is_file()})
    if limit:
        # 이름순 앞쪽만 몰리지 않게 전체에서 고르게 건너뛰며 고른다
        files = files[::max(1, len(files) // limit)]
    stats = {"written": 0, "not_pe": 0, "failed": []}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out:
        for p in files:
            if limit is not None and stats["written"] >= limit:
                break
            try:
                if identify(p) != "pe":
                    stats["not_pe"] += 1
                    continue
                raw = extract_file(p)
            except (FeatureError, OSError) as e:
                stats["failed"].append((p.name, str(e)))
                continue
            # 기준선은 시스템 파일이라 이름만 남긴다 (전체 경로는 남기지 않음)
            raw["file_name"] = p.name
            if label is not None:
                raw["label"] = label
            out.write(json.dumps(raw, ensure_ascii=False) + "\n")
            stats["written"] += 1
    return stats


def summarize(jsonl_path):
    """기준선 요약: 백신이 의심 신호로 보는 항목이 정상 파일에서 얼마나 나오는지."""
    rows = [json.loads(line) for line in Path(jsonl_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    n = len(rows)
    if n == 0:
        return {"files": 0}

    def pct(cond):
        return round(100 * sum(1 for r in rows if cond(r)) / n, 1)

    def dll_chars(r):
        return r.get("header", {}).get("optional", {}).get("dll_characteristics", []) or []

    def sections(r):
        return r.get("section", {}).get("sections", []) or []

    machines = {}
    for r in rows:
        m = r.get("header", {}).get("coff", {}).get("machine", "?")
        machines[m] = machines.get(m, 0) + 1

    return {
        "files": n,
        "machine": machines,
        "ASLR(DYNAMIC_BASE)%": pct(lambda r: "DYNAMIC_BASE" in dll_chars(r)),
        "DEP(NX_COMPAT)%": pct(lambda r: "NX_COMPAT" in dll_chars(r)),
        "CFG(GUARD_CF)%": pct(lambda r: "GUARD_CF" in dll_chars(r)),
        "파일 안 서명%": pct(lambda r: r.get("authenticode", {}).get("num_certs", 0) > 0),
        "쓰기+실행 섹션%": pct(lambda r: any(
            "MEM_WRITE" in s.get("props", []) and "MEM_EXECUTE" in s.get("props", []) for s in sections(r))),
        "시작 섹션이 .text 아님%": pct(lambda r: r.get("section", {}).get("entry") not in (".text", "")),
        "엔트로피 7 이상 섹션%": pct(lambda r: any(s.get("entropy", 0) >= 7 for s in sections(r))),
        "평균 파일 엔트로피": round(sum(r.get("general", {}).get("entropy", 0) for r in rows) / n, 2),
    }