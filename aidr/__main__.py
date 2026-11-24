"""명령줄 실행: python -m aidr scan <폴더> [--hashes 목록] [--out 결과.json]"""
from aidr.yara_scan import load_rules
import argparse
import json
import sys
from pathlib import Path

from aidr.hashes import load_hash_list
from aidr.scanner import scan_folder

DEFAULT_HASHES = Path(__file__).resolve().parent.parent / "hashes" / "known_bad.txt"
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "aidr.yar"

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aidr")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="폴더 검사")
    scan.add_argument("folder", type=Path)
    scan.add_argument("--hashes", type=Path, default=DEFAULT_HASHES)
    scan.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    scan.add_argument("--out", type=Path, help="결과 JSON 파일 경로 (없으면 화면에 출력)")
    args = parser.parse_args(argv)

    if not args.folder.is_dir():
        print(f"폴더가 아님: {args.folder}", file=sys.stderr)
        return 2

    bad = load_hash_list(args.hashes) if args.hashes.exists() else set()
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