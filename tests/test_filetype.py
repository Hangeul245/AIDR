from aidr.filetype import extension_mismatch, identify


def make_pe(path):
    """최소한의 가짜 PE: MZ + 0x3c에 e_lfanew=0x40 + 0x40 위치에 PE\\0\\0."""
    data = bytearray(0x80)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\x00\x00"
    path.write_bytes(bytes(data))
    return path


def test_pe(tmp_path):
    assert identify(make_pe(tmp_path / "a.exe")) == "pe"


def test_mz_without_pe_signature(tmp_path):
    # MZ로 시작해도 PE 서명이 없으면 PE가 아니다
    p = tmp_path / "fake.bin"
    p.write_bytes(b"MZ" + b"cmd.exe /c hello" * 10)
    assert identify(p) == "mz"


def test_e_lfanew_out_of_range(tmp_path):
    data = bytearray(0x80)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0xFFFFFF).to_bytes(4, "little")   # 파일 밖을 가리킴
    p = tmp_path / "broken.exe"
    p.write_bytes(bytes(data))
    assert identify(p) == "mz"


def test_other_magics(tmp_path):
    cases = {
        "a.docx": (b"PK\x03\x04" + b"\x00" * 30, "zip"),
        "a.doc": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 30, "ole"),
        "a.pdf": (b"%PDF-1.7\n", "pdf"),
        "a.so": (b"\x7fELF" + b"\x00" * 30, "elf"),
    }
    for name, (data, expected) in cases.items():
        p = tmp_path / name
        p.write_bytes(data)
        assert identify(p) == expected, name


def test_script_by_extension(tmp_path):
    p = tmp_path / "run.ps1"
    p.write_text("Write-Output hi", encoding="utf-8")
    assert identify(p) == "script"


def test_name_does_not_fool_us(tmp_path):
    # 이름이 photo.jpg여도 내용이 PE면 PE + 확장자 위장 신호
    p = make_pe(tmp_path / "photo.jpg")
    assert identify(p) == "pe"
    assert extension_mismatch(p, "pe") is True


def test_normal_exe_is_not_mismatch(tmp_path):
    p = make_pe(tmp_path / "setup.exe")
    assert extension_mismatch(p, "pe") is False