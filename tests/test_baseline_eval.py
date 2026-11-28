import json
import sys
import types

import numpy as np
import pytest

from aidr import baseline_eval

I386 = baseline_eval.I386
AMD64 = "IMAGE_FILE_MACHINE_AMD64"


def row(name, machine=I386, value=0.0):
    return {"file_name": name, "header": {"coff": {"machine": machine}}, "v": value}


class FakeExtractor:
    """raw 특징의 v 값 하나를 벡터로 돌려주는 가짜 추출기. v가 None이면 실패."""
    dim = 1

    def process_raw_features(self, raw):
        if raw["v"] is None:
            raise KeyError("v")
        return [raw["v"]]


class FakeBooster:
    def predict(self, X):
        return X[:, 0]  # 벡터 값을 그대로 점수로


def test_split_by_machine_keeps_only_i386():
    keep, skipped = baseline_eval.split_by_machine([row("a.dll"), row("b.dll", AMD64), row("c.exe", AMD64)])
    assert [r["file_name"] for r in keep] == ["a.dll"]
    assert skipped == {AMD64: 2}


def test_vectorize_records_failures():
    X, names, failed = baseline_eval.vectorize([row("ok.dll", value=0.3), row("bad.dll", value=None)], FakeExtractor())
    assert X.shape == (1, 1) and names == ["ok.dll"]
    assert failed[0][0] == "bad.dll"


def test_evaluate_uses_strict_greater_than():
    scores = np.array([0.1, 0.4, 0.9])
    levels = {"low": {"threshold": 0.4}, "high": {"threshold": 0.95}}
    result = baseline_eval.evaluate(scores, ["a", "b", "c"], levels)
    assert result["low"]["fp_files"] == ["c"]  # 0.4는 임계값과 같아서 오탐 아님
    assert result["low"]["fp"] == 1
    assert result["low"]["expected_fp_pc"] == round(1 / 3 * 20000, 2)
    assert result["high"]["fp"] == 0 and result["high"]["fp_files"] == []


def test_main_writes_report_and_hides_threshold(tmp_path, monkeypatch, capsys):
    secret_thr = 0.123456789
    thresholds = {"model_sha256": "x", "rule": "score > threshold",
                  "levels": {"service": {"threshold": secret_thr}}}
    monkeypatch.setattr(baseline_eval, "load_checked", lambda d: (FakeBooster(), thresholds))
    monkeypatch.setitem(sys.modules, "thrember", types.SimpleNamespace(PEFeatureExtractor=FakeExtractor))

    feats = tmp_path / "f.jsonl"
    lines = [row("a.dll", value=0.05), row("b.dll", value=0.9), row("x64.dll", AMD64, 0.9)]
    feats.write_text("\n".join(json.dumps(r) for r in lines) + "\nnot json\n", encoding="utf-8")

    baseline_eval.main([str(feats), str(tmp_path), "--name", "test"])

    report = json.loads((tmp_path / "baseline_test.json").read_text(encoding="utf-8"))
    assert report["scored"] == 2 and report["bad_json"] == 1
    assert report["skipped_machine"] == {AMD64: 1}
    assert report["levels"]["service"]["fp_files"] == ["b.dll"]
    assert not list(tmp_path.glob("*.tmp"))
    assert str(secret_thr) not in capsys.readouterr().out  # 임계값 숫자는 화면에 안 찍음


def test_main_stops_when_nothing_to_score(tmp_path, monkeypatch):
    thresholds = {"model_sha256": "x", "rule": "r", "levels": {}}
    monkeypatch.setattr(baseline_eval, "load_checked", lambda d: (FakeBooster(), thresholds))
    monkeypatch.setitem(sys.modules, "thrember", types.SimpleNamespace(PEFeatureExtractor=FakeExtractor))
    feats = tmp_path / "f.jsonl"
    feats.write_text(json.dumps(row("x64.dll", AMD64, 0.5)) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        baseline_eval.main([str(feats), str(tmp_path), "--name", "empty"])
