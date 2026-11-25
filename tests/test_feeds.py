import pytest

from aidr import feeds

# 진짜 악성 해시가 아닌 가짜 값
A = "a" * 64
B = "b" * 64
C = "c" * 64


def test_parse_keeps_only_sha256():
    records = [
        {"sha256_hash": A, "file_name": "x.exe"},
        {"sha256_hash": B.upper()},
        {"sha256_hash": "not-a-hash"},
        "garbage",
    ]
    assert feeds.parse_sha256s(records) == {A, B}


def test_fetch_merges_types_and_skips_no_results(monkeypatch):
    answers = {
        "exe": {"query_status": "ok", "data": [{"sha256_hash": A}]},
        "dll": {"query_status": "no_results"},
    }
    monkeypatch.setattr(feeds, "query_api", lambda form: answers[form["file_type"]])
    assert feeds.fetch_recent_hashes() == {A}


def test_fetch_error_status_raises(monkeypatch):
    monkeypatch.setattr(feeds, "query_api", lambda form: {"query_status": "illegal_file_type"})
    with pytest.raises(feeds.FeedError):
        feeds.fetch_recent_hashes()


def test_merge_keeps_old_and_counts_new(tmp_path):
    out = tmp_path / "mb.txt"
    feeds.merge_into(out, {A, B})
    total, added = feeds.merge_into(out, {B, C})
    assert (total, added) == (3, 1)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("#")
    assert set(lines[1:]) == {A, B, C}


def test_empty_result_keeps_old_list(tmp_path):
    out = tmp_path / "mb.txt"
    feeds.merge_into(out, {A})
    with pytest.raises(feeds.FeedError):
        feeds.merge_into(out, set())
    assert A in out.read_text(encoding="utf-8")


def test_missing_key(monkeypatch):
    monkeypatch.delenv(feeds.KEY_ENV, raising=False)
    with pytest.raises(feeds.FeedError):
        feeds.query_api({"query": "get_file_type"})


def test_error_message_hides_key(monkeypatch):
    secret = "SECRET-KEY-1234"
    monkeypatch.setenv(feeds.KEY_ENV, secret)

    def boom(*args, **kwargs):
        raise feeds.urllib.error.URLError("down")

    monkeypatch.setattr(feeds.urllib.request, "urlopen", boom)
    with pytest.raises(feeds.FeedError) as e:
        feeds.query_api({"query": "get_file_type"})
    assert secret not in str(e.value)