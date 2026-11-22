"""해시 계산과 악성 해시 목록."""
import hashlib
import re
from pathlib import Path

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """큰 파일도 메모리를 아끼도록 1MB씩 나눠 읽어서 SHA-256을 구한다."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def load_hash_list(path: Path) -> set[str]:
    """한 줄에 해시 하나. '#'으로 시작하는 줄과 빈 줄은 무시. 형식이 틀린 줄도 무시."""
    hashes = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if _SHA256_RE.match(line):
            hashes.add(line)
    return hashes