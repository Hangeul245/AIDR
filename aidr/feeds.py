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
# 1단계 범위는 PE. 스크립트·문서 형식은 4주차 추출기 때 추가
FILE_TYPES = ("exe", "dll")
LIMIT = 100  # API 최대값
# 매일 바뀌는 데이터라 저장소 바깥(C:\airm\feeds)에 둔다
DEFAULT_OUT = Path(__file__).resolve().parent.parent.parent / "feeds" / "malwarebazaar_sha256.txt"
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
    """형식별로 최근 샘플의 해시를 모은다."""
    found = set()
    for ft in file_types:
        resp = query_api({"query": "get_file_type", "file_type": ft, "limit": str(limit)})
        status = resp.get("query_status")
        if status == "no_results":
            continue
        if status != "ok":
            raise FeedError(f"{ft}: {status}")
        found |= parse_sha256s(resp.get("data") or [])
    return found


def merge_into(path, new_hashes):
    """기존 목록에 새 해시를 합친다. 받은 게 0개면 기존 목록을 건드리지 않는다."""
    if not new_hashes:
        raise FeedError("받은 해시가 0개, 기존 목록 유지")
    path = Path(path)
    old = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if SHA256_RE.match(line):
                old.add(line)
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


def main():
    try:
        hashes = fetch_recent_hashes()
        total, added = merge_into(DEFAULT_OUT, hashes)
    except FeedError as e:
        print(f"MalwareBazaar 수집 실패: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(f"MalwareBazaar: 받은 {len(hashes)}개, 새로 추가 {added}개, 전체 {total}개 → {DEFAULT_OUT}")


if __name__ == "__main__":
    main()