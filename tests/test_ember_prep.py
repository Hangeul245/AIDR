from datetime import date
import pytest
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