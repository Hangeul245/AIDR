import json
from datetime import date

import numpy as np
import pytest

from aidr import ember_prep
from aidr.ember_prep import parse_name, list_files

def test_parse_name_train():
    assert parse_name("2024-03-17_2024-03-23_Win32_train.jsonl") == (date(2024, 3, 17), "Win32", "train")

def test_parse_name_challenge():
    assert parse_name("2023-09-24_2023-09-30_challenge_malicious.jsonl") == (date(2023, 9, 24), None, "challenge")

@pytest.mark.parametrize("name", [
    "2024-03-17_2024-03-23_Win32_train_backup.jsonl",
    "2024-03-17_2024-03-23_Win32_train.json",
    "2024-3-17_2024-03-23_Win32_train.jsonl",
    "2024-03-17_2024-03-23_Win32_pretrain.jsonl",
    "notes.jsonl",
])

#이상한 이름은 전부 None
def test_parse_name_rejects(name):
    assert parse_name(name) is None

#Win32만, 날짜순으로 고르는지
def make_files(folder, names):
    for n in names:
        (folder / n).touch()

NAMES = [
    "2024-03-24_2024-03-30_Win32_train.jsonl",
    "2024-03-17_2024-03-23_Win32_train.jsonl",
    "2024-03-17_2024-03-23_Win64_train.jsonl",
    "2024-09-22_2024-09-28_Win32_test.jsonl",
    "2023-09-24_2023-09-30_challenge_malicious.jsonl",
    "2024-03-17_2024-03-23_Win32_train_backup.jsonl",
]

def test_list_files_train(tmp_path):
    make_files(tmp_path, NAMES)
    got = [p.name for p in list_files(tmp_path, "train")]
    assert got == [
        "2024-03-17_2024-03-23_Win32_train.jsonl",
        "2024-03-24_2024-03-30_Win32_train.jsonl",
    ]

def test_list_files_challenge(tmp_path):
    make_files(tmp_path, NAMES)
    got = [p.name for p in list_files(tmp_path, "challenge")]
    assert got == ["2023-09-24_2023-09-30_challenge_malicious.jsonl"]

def test_list_files_unknown_subset(tmp_path):
    with pytest.raises(ValueError):
        list_files(tmp_path, "tset")

#두 번 불러도 결과가 쌓이지 않는지
def test_list_files_called_twice(tmp_path):
    make_files(tmp_path, NAMES)
    list_files(tmp_path, "train")
    got = [p.name for p in list_files(tmp_path, "test")]
    assert got == ["2024-09-22_2024-09-28_Win32_test.jsonl"]

def fake_raw():
    thrember = pytest.importorskip("thrember")
    data = bytearray(0x100)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    return thrember.PEFeatureExtractor().raw_features(bytes(data))
#상태 네 가지가 맞게 나오는지
def test_vectorize_line_statuses():
    ember_prep._init_worker()
    raw = fake_raw()
    ok = json.dumps(dict(raw, label=1, file_type="Win32"))
    nolabel = json.dumps(dict(raw, label=None, file_type="Win32"))
    other = json.dumps(dict(raw, label=1, file_type="APK"))

    status, value, label = ember_prep.vectorize_line(ok)
    assert status == "ok" and label == 1 and len(value) == 2568 * 4
    assert ember_prep.vectorize_line(nolabel)[0] == "nolabel"
    assert ember_prep.vectorize_line(other)[:2] == ("other", "APK")
    assert ember_prep.vectorize_line("{broken")[0] == "fail"
    assert ember_prep.vectorize_line(json.dumps(dict(raw, label=True, file_type="Win32")))[0] == "nolabel"

#세트 전체를 처리하면 개수·순서·파일이 맞는지
def test_vectorize_subset_counts_and_order(tmp_path):
    raw = fake_raw()
    lines = [
        json.dumps(dict(raw, label=1, file_type="Win32")),
        json.dumps(dict(raw, label=None, file_type="Win32")),
        json.dumps(dict(raw, label=0, file_type="Win32")),
        "{broken",
    ]
    src = tmp_path / "2024-03-17_2024-03-23_Win32_train.jsonl"
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    meta = ember_prep.vectorize_subset([src], tmp_path / "out", "train", processes=0)
    assert meta["totals"] == {"ok": 2, "nolabel": 1, "other": 0, "fail": 1}
    assert meta["failures_first"][0]["line"] == 4

    X, y, _ = ember_prep.read_subset(tmp_path / "out", "train")
    assert X.shape == (2, 2568)
    assert list(y) == [1, 0]
    assert not list((tmp_path / "out").glob("*.tmp"))

#챌린지는 Win32만 남는지
def test_vectorize_subset_challenge_keeps_win32(tmp_path):
    raw = fake_raw()
    lines = [
        json.dumps(dict(raw, label=1, file_type="Win32")),
        json.dumps(dict(raw, label=1, file_type="Win64")),
        json.dumps(dict(raw, label=1, file_type="APK")),
        json.dumps(dict(raw, label=1)),
    ]
    src = tmp_path / "2023-09-24_2023-09-30_challenge_malicious.jsonl"
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    meta = ember_prep.vectorize_subset([src], tmp_path / "out", "challenge",
                                       processes=0, require_type=True)
    assert meta["rows"] == 1
    assert meta["files"][0]["other_types"] == {"Win64": 1, "APK": 1, "file_type 없음": 1}

#메타와 라벨 수가 다르면 멈추는지
def test_read_subset_detects_mismatch(tmp_path):
    np.zeros((2, 3), dtype=np.float32).tofile(tmp_path / "X_t.dat")
    np.zeros(3, dtype=np.int32).tofile(tmp_path / "y_t.dat")
    (tmp_path / "t_meta.json").write_text(json.dumps({"rows": 2, "dim": 3}), encoding="utf-8")
    with pytest.raises(ValueError):
        ember_prep.read_subset(tmp_path, "t")