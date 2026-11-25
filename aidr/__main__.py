"""명령줄 실행
python -m aidr scan <폴더> [--hashes 목록 ...] [--rules 규칙] [--out 결과.json]
python -m aidr update   (MalwareBazaar 해시 목록 갱신)
"""
import argparse
import json
import sys
from pathlib import Path

from aidr import feeds
from aidr.hashes import load_hash_list
from aidr.scanner import scan_folder
from aidr.yara_scan import load_rules

ROOT = Path(__file__).resolve().parent.parent
# 기본: 저장소의 고정 목록(EICAR) + 저장소 바깥의 MalwareBazaar 누적 목록
DEFAULT_HASHES = [ROOT / "hashes" / "known_bad.txt", feeds.DEFAULT_OUT]
DEFAULT_RULES = ROOT / "rules" / "aidr.yar"


def load_all_hashes(paths):
    """여러 해시 목록을 합친다. 없는 파일은 건너뛰고 알려 준다."""
    bad = set()
    for p in paths:
        if p.exists():
            found = set(load_hash_list(p))
            bad |= found
            print(f"해시 목록 {len(found)}개: {p}", file=sys.stderr)
        else:
            print(f"해시 목록 없음, 건너뜀: {p}", file=sys.stderr)
    return bad


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aidr")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="폴더 검사")
    scan.add_argument("folder", type=Path)
    scan.add_argument(
        "--hashes", type=Path, action="append",
        help="악성 해시 목록. 여러 번 지정 가능 (지정 안 하면 기본 목록 + MalwareBazaar 목록)",
    )
    scan.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    scan.add_argument("--out", type=Path, help="결과 JSON 파일 경로 (없으면 화면에 출력)")

    sub.add_parser("update", help="MalwareBazaar 해시 목록 갱신")

    args = parser.parse_args(argv)

    if args.command == "update":
        feeds.main()
        return 0

    if not args.folder.is_dir():
        print(f"폴더가 아님: {args.folder}", file=sys.stderr)
        return 2

    bad = load_all_hashes(args.hashes or DEFAULT_HASHES)
    rules = None
    if args.rules.exists():
        rules = load_rules(args.rules)
    else:
        print(f"YARA 규칙 파일 없음, YARA 검사 생략: {args.rules}", file=sys.stderr)
    report = scan_folder(args.folder, bad, rules)
    text = json.dumps(report, ensure_ascii=False, indent=2)

    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"검사 완료: {report['total']}개, 결과 저장 → {args.out}")
        print("요약:", report["summary"])
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())