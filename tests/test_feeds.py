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


def test_fetch_splits_types_and_skips_no_results(monkeypatch):
    answers = {
        "exe": {"query_status": "ok", "data": [{"sha256_hash": A}]},
        "dll": {"query_status": "no_results"},
    }
    monkeypatch.setattr(feeds, "query_api", lambda form: answers[form["file_type"]])
    assert feeds.fetch_recent_hashes() == ({"exe": {A}, "dll": set()}, {})


def test_fetch_error_status_is_recorded(monkeypatch):
    monkeypatch.setattr(feeds, "query_api", lambda form: {"query_status": "illegal_file_type"})
    by_type, failures = feeds.fetch_recent_hashes()
    assert by_type == {}
    assert failures == {"exe": "illegal_file_type", "dll": "illegal_file_type"}


def test_fetch_keeps_other_type_when_one_fails(monkeypatch):
    def fake(form):
        if form["file_type"] == "exe":
            raise feeds.FeedError("HTTP 503")
        return {"query_status": "ok", "data": [{"sha256_hash": B}]}

    monkeypatch.setattr(feeds, "query_api", fake)
    by_type, failures = feeds.fetch_recent_hashes()
    assert by_type == {"dll": {B}}  # exe가 먼저 실패해도 dll은 요청한다
    assert failures == {"exe": "HTTP 503"}


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

def _setup_main(monkeypatch, tmp_path, by_type, failures):
    out = tmp_path / "mb.txt"
    log = tmp_path / "update.log"
    monkeypatch.setattr(feeds, "DEFAULT_OUT", out)
    monkeypatch.setattr(feeds, "LOG_PATH", log)
    monkeypatch.setattr(feeds, "fetch_recent_hashes", lambda: (by_type, failures))
    return out, log


def test_main_logs_new_count_per_type(monkeypatch, tmp_path):
    out, log = _setup_main(monkeypatch, tmp_path, {"exe": {A, B}, "dll": {C}}, {})
    feeds.merge_into(out, {A})  # A는 이미 있던 해시
    feeds.main()
    line = log.read_text(encoding="utf-8").splitlines()[-1]
    assert "exe 받음 2 새로 1" in line
    assert "dll 받음 1 새로 1" in line
    assert "전체 3" in line


def test_main_saves_other_type_and_exits_1_on_failure(monkeypatch, tmp_path):
    out, log = _setup_main(monkeypatch, tmp_path, {"exe": {A}}, {"dll": "HTTP 503"})
    with pytest.raises(SystemExit) as e:
        feeds.main()
    assert e.value.code == 1
    assert A in feeds.read_list(out)  # 실패한 형식이 있어도 받은 건 저장
    assert "dll 실패(HTTP 503)" in log.read_text(encoding="utf-8")


def test_main_all_failed_keeps_old_list(monkeypatch, tmp_path):
    out, log = _setup_main(monkeypatch, tmp_path, {}, {"exe": "HTTP 503", "dll": "HTTP 503"})
    feeds.merge_into(out, {A})
    with pytest.raises(SystemExit):
        feeds.main()
    assert feeds.read_list(out) == {A}
    assert "저장 안 함" in log.read_text(encoding="utf-8")


def test_log_has_no_key(monkeypatch, tmp_path):
    secret = "SECRET-KEY-1234"
    monkeypatch.setenv(feeds.KEY_ENV, secret)
    _, log = _setup_main(monkeypatch, tmp_path, {}, {"exe": "HTTP 401", "dll": "HTTP 401"})
    with pytest.raises(SystemExit):
        feeds.main()
    text = log.read_text(encoding="utf-8")
    assert secret not in text
    assert "mb-api" not in text
