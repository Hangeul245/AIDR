import json

from aidr import hashes, scanner
from aidr.__main__ import main


def test_hash_match_is_malicious(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("pretend malicious", encoding="utf-8")
    good = tmp_path / "good.txt"
    good.write_text("hello", encoding="utf-8")

    bad_set = {hashes.sha256_file(bad)}
    report = scanner.scan_folder(tmp_path, bad_set)

    by_name = {r["path"].split("/")[-1].split("\\")[-1]: r for r in report["results"]}
    assert by_name["bad.txt"]["verdict"] == "악성"
    assert by_name["good.txt"]["verdict"] == "정상"
    assert report["summary"]["악성"] == 1
    assert report["total"] == 2


def test_unreadable_file_is_never_normal(tmp_path, monkeypatch):
    f = tmp_path / "locked.bin"
    f.write_bytes(b"data")

    def boom(path, chunk_size=0):
        raise PermissionError("locked")

    monkeypatch.setattr(hashes, "sha256_file", boom)
    report = scanner.scan_folder(tmp_path, set())
    assert report["results"][0]["verdict"] == "검토 필요"


def test_load_hash_list_ignores_comments_and_garbage(tmp_path):
    good = "a" * 64
    p = tmp_path / "list.txt"
    p.write_text(f"# 설명\n{good.upper()}  # 대문자도 OK\nnot-a-hash\n\n", encoding="utf-8")
    assert hashes.load_hash_list(p) == {good}


def test_cli_writes_json(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")
    out = tmp_path / "result.json"
    empty_list = tmp_path / "empty.txt"
    empty_list.write_text("", encoding="utf-8")

    assert main(["scan", str(target), "--hashes", str(empty_list), "--out", str(out)]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["total"] == 1
    assert set(report["summary"]) == {"정상", "검토 필요", "의심", "악성"}