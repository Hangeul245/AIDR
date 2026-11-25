import hashlib
import json
from pathlib import Path

from aidr.__main__ import main


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_scan(tmp_path, *hash_lists):
    folder = tmp_path / "scan"
    folder.mkdir()
    (folder / "one.bin").write_bytes(b"AIDR fake one")
    (folder / "two.bin").write_bytes(b"AIDR fake two")
    (folder / "three.bin").write_bytes(b"AIDR fake three")
    out = tmp_path / "result.json"
    argv = ["scan", str(folder), "--rules", str(tmp_path / "no_rules.yar"), "--out", str(out)]
    for p in hash_lists:
        argv += ["--hashes", str(p)]
    assert main(argv) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    return {Path(r["path"]).name: r["verdict"] for r in report["results"]}


def test_multiple_hash_lists_are_merged(tmp_path):
    # 고정 목록과 피드 목록에 각각 다른 파일이 있어도 둘 다 잡혀야 한다
    known = tmp_path / "known_bad.txt"
    feed = tmp_path / "feed.txt"
    known.write_text(sha(b"AIDR fake one") + "\n", encoding="utf-8")
    feed.write_text("# feed\n" + sha(b"AIDR fake two") + "\n", encoding="utf-8")
    verdicts = run_scan(tmp_path, known, feed)
    assert verdicts == {"one.bin": "악성", "two.bin": "악성", "three.bin": "정상"}


def test_missing_hash_list_is_skipped(tmp_path):
    # 피드를 아직 안 받았어도 검사는 돌아가야 한다
    known = tmp_path / "known_bad.txt"
    known.write_text(sha(b"AIDR fake one") + "\n", encoding="utf-8")
    verdicts = run_scan(tmp_path, known, tmp_path / "not_yet.txt")
    assert verdicts["one.bin"] == "악성"