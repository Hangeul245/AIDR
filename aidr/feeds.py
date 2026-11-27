"""공개 위협 피드(MalwareBazaar)에서 악성 해시만 받아 온다. 샘플 파일은 절대 받지 않는다."""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_URL = "https://mb-api.abuse.ch/api/v1/"
KEY_ENV = "MB_AUTH_KEY"

FILE_TYPES = ("exe", "dll")
LIMIT = 100  # API 최대값

DEFAULT_OUT = Path(__file__).resolve().parent.parent.parent / "feeds" / "malwarebazaar_sha256.txt"
LOG_PATH = DEFAULT_OUT.parent / "update.log"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FeedError(Exception):
    pass


def query_api(form, timeout=30):
    """MalwareBazaar API에 POST 한 번. 키는 헤더로만 보낸다."""
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        raise FeedError(f"환경 변수 {KEY_ENV}가 없음")
    req = urllib.request.Request(
        API_URL,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Auth-Key": key, "User-Agent": "AIDR"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise FeedError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise FeedError(f"연결 실패: {type(e).__name__}") from None
    except ValueError:
        raise FeedError("응답이 JSON이 아님") from None


def parse_sha256s(records):
    """응답 data 목록에서 sha256_hash만 뽑는다. 파일 이름 같은 다른 칸은 쓰지 않는다."""
    found = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        value = str(rec.get("sha256_hash", "")).strip().lower()
        if SHA256_RE.match(value):
            found.add(value)
    return found


def fetch_recent_hashes(file_types=FILE_TYPES, limit=LIMIT):
    """형식별로 최근 샘플의 해시를 모은다. 한 형식이 실패해도 나머지는 계속한다.

    반환: (by_type, failures)
      by_type  = {"exe": {해시...}, "dll": set()}   성공한 형식만
      failures = {"dll": "HTTP 503"}                 실패한 형식과 이유
    """
    by_type = {}
    failures = {}
    for ft in file_types:
        try:
            resp = query_api({"query": "get_file_type", "file_type": ft, "limit": str(limit)})
        except FeedError as e:
            failures[ft] = str(e)
            continue
        status = resp.get("query_status")
        if status == "no_results":
            by_type[ft] = set()
            continue
        if status != "ok":
            failures[ft] = str(status)
            continue
        by_type[ft] = parse_sha256s(resp.get("data") or [])
    return by_type, failures


def read_list(path):
    """해시 목록 파일을 집합으로 읽는다. 파일이 없으면 빈 집합."""
    path = Path(path)
    found = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if SHA256_RE.match(line):
                found.add(line)
    return found


def merge_into(path, new_hashes):
    """기존 목록에 새 해시를 합친다. 받은 게 0개면 기존 목록을 건드리지 않는다."""
    if not new_hashes:
        raise FeedError("받은 해시가 0개, 기존 목록 유지")
    path = Path(path)
    old = read_list(path)
    merged = old | set(new_hashes)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tmp = path.with_suffix(".tmp")
    # 주석은 영어로만 (해시 목록을 읽는 쪽의 인코딩과 상관없게)
    tmp.write_text(
        f"# MalwareBazaar get_file_type (accumulated), last update {stamp}\n"
        + "".join(h + "\n" for h in sorted(merged)),
        encoding="utf-8",
    )
    tmp.replace(path)  # 다 쓴 다음 한 번에 바꿔치기 (중간에 끊겨도 기존 목록 보존)
    return len(merged), len(merged) - len(old)


def write_log(path, line):
    """로그 파일 끝에 한 줄 붙인다. 키와 URL은 넣지 않는다."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def main():
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
    by_type, failures = fetch_recent_hashes()
    old = read_list(DEFAULT_OUT)

    parts = []
    for ft in FILE_TYPES:
        if ft in failures:
            parts.append(f"{ft} 실패({failures[ft]})")
        else:
            got = by_type.get(ft, set())
            parts.append(f"{ft} 받음 {len(got)} 새로 {len(got - old)}")

    received = set().union(*by_type.values())
    saved = True
    try:
        total, _ = merge_into(DEFAULT_OUT, received)
        parts.append(f"전체 {total}")
    except FeedError as e:
        saved = False
        parts.append(f"저장 안 함({e})")

    line = f"{stamp} | " + " | ".join(parts)
    write_log(LOG_PATH, line)
    print(line)
    if failures or not saved:
        raise SystemExit(1)  # 작업 스케줄러의 "마지막 실행 결과"에 실패로 보이게


if __name__ == "__main__":
    main()