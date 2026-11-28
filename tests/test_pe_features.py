import json

import pytest

from aidr import pe_features

EMBER_KEYS = {
    "sha256", "general", "histogram", "byteentropy", "strings", "header", "section",
    "imports", "exports", "datadirectories", "richheader", "authenticode", "pefilewarnings",
}


def make_fake_pe(path):
    # MZ + 0x3c 위치의 주소 + 그 주소의 PE 서명만 있는 가짜 PE (실행 불가)
    data = bytearray(0x100)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")  # I386
    path.write_bytes(bytes(data))
    return path


def test_extract_has_ember_keys(tmp_path):
    pytest.importorskip("thrember")
    p = make_fake_pe(tmp_path / "fake.exe")
    raw = pe_features.extract_file(p)
    assert EMBER_KEYS <= set(raw)


def test_folder_skips_non_pe_and_writes_jsonl(tmp_path):
    pytest.importorskip("thrember")
    src = tmp_path / "src"
    src.mkdir()
    make_fake_pe(src / "a.exe")
    (src / "b.dll").write_bytes(b"not a pe at all")
    (src / "c.txt").write_bytes(b"ignored")
    out = tmp_path / "out.jsonl"
    stats = pe_features.extract_folder(src, out, label=0)
    assert stats["written"] == 1 and stats["not_pe"] == 1 and stats["failed"] == []
    row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert row["file_name"] == "a.exe" and row["label"] == 0


def test_too_large_file_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(pe_features, "MAX_BYTES", 10)
    p = make_fake_pe(tmp_path / "big.exe")
    with pytest.raises(pe_features.FeatureError):
        pe_features.extract_file(p)


def test_summarize(tmp_path):
    # thrember 없이 요약 계산만 확인 (손으로 만든 특징 두 줄)
    rows = [
        {"general": {"entropy": 6.0},
         "header": {"coff": {"machine": "IMAGE_FILE_MACHINE_I386"},
                    "optional": {"dll_characteristics": ["DYNAMIC_BASE", "NX_COMPAT"]}},
         "authenticode": {"num_certs": 1},
         "section": {"entry": ".text", "sections": [{"props": ["MEM_EXECUTE", "MEM_READ"], "entropy": 6.1}]}},
        {"general": {"entropy": 7.0},
         "header": {"coff": {"machine": "IMAGE_FILE_MACHINE_I386"}, "optional": {"dll_characteristics": []}},
         "authenticode": {"num_certs": 0},
         "section": {"entry": "UPX1", "sections": [{"props": ["MEM_EXECUTE", "MEM_WRITE"], "entropy": 7.9}]}},
    ]
    p = tmp_path / "base.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    s = pe_features.summarize(p)
    assert s["files"] == 2
    assert s["ASLR(DYNAMIC_BASE)%"] == 50.0
    assert s["쓰기+실행 섹션%"] == 50.0
    assert s["시작 섹션이 .text 아님%"] == 50.0
    assert s["평균 파일 엔트로피"] == 6.5

    

def test_signify_version_supports_thrember():
    # thrember는 인증서 목록을 리스트처럼 자른다(certs[:-1]).
    # signify 0.8부터 CertificateStore가 리스트가 아니게 바뀌어 서명된 PE만 추출 실패함 (2026-11-25)
    pytest.importorskip("thrember")
    from signify.x509 import CertificateStore
    assert issubclass(CertificateStore, list)

def test_folder_recursive_finds_nested_files(tmp_path, monkeypatch):
    # thrember 없이 폴더 찾기만 확인 (추출은 가짜로 대신)
    monkeypatch.setattr(pe_features, "identify", lambda p: "pe")
    monkeypatch.setattr(pe_features, "extract_file", lambda p: {})
    nested = tmp_path / "src" / "Program" / "bin"
    nested.mkdir(parents=True)
    (nested / "app.exe").write_bytes(b"x")
    out = tmp_path / "out.jsonl"

    assert pe_features.extract_folder(tmp_path / "src", out)["written"] == 0
    assert pe_features.extract_folder(tmp_path / "src", out, recursive=True)["written"] == 1
    row = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert row["file_name"] == "app.exe"  # 하위 폴더 경로는 남기지 않음
