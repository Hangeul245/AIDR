"""파일 형식 식별 (매직 바이트).

파일 이름(확장자)은 공격자가 마음대로 바꿀 수 있으므로,
파일 앞부분의 실제 바이트로 형식을 판단한다.
"""
from pathlib import Path

# (시작 바이트, 형식 이름)
MAGIC = [
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),   # 옛 오피스(doc/xls/ppt), msi
    (b"PK\x03\x04", "zip"),                        # zip, docx/xlsx/pptx, jar, apk
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
]

SCRIPT_EXTS = {".ps1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".hta", ".wsf"}

# 실행 파일인데 이런 확장자를 달고 있으면 위장 의심
DOC_LIKE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".txt",
                 ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".hwp", ".mp3", ".mp4"}


def _is_pe(head: bytes, path: Path) -> bool:
    """MZ로 시작하고, 0x3c 위치(e_lfanew)가 가리키는 곳에 PE\\0\\0 서명이 있으면 PE."""
    if len(head) < 0x40:
        return False
    e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
    if e_lfanew < 0x40 or e_lfanew > path.stat().st_size - 4:
        return False
    with open(path, "rb") as f:
        f.seek(e_lfanew)
        return f.read(4) == b"PE\x00\x00"


def identify(path: Path) -> str:
    """파일 형식을 문자열로 돌려준다. 파일을 실행하지 않고 앞부분만 읽는다."""
    path = Path(path)
    with open(path, "rb") as f:
        head = f.read(512)

    if head[:2] == b"MZ":
        return "pe" if _is_pe(head, path) else "mz"   # mz = MZ로 시작하지만 PE 서명 없음
    for magic, name in MAGIC:
        if head.startswith(magic):
            return name
    if path.suffix.lower() in SCRIPT_EXTS:
        return "script"
    return "unknown"


def extension_mismatch(path: Path, file_type: str) -> bool:
    """실행 파일(PE)인데 문서·이미지 확장자를 달고 있으면 True (약한 신호)."""
    ext = Path(path).suffix.lower()
    return file_type in ("pe", "mz") and ext in DOC_LIKE_EXTS