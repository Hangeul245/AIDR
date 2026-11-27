import json

import lightgbm as lgb
import numpy as np
import pytest

from aidr.ember_eval import load_checked, measure, per_week, predict_chunks
from aidr.ember_threshold import file_sha256


def tiny_booster():
    rng = np.random.default_rng(0)
    X = rng.random((200, 3)).astype(np.float32)
    y = (X[:, 0] > 0.5).astype(np.int32)
    return lgb.train({"objective": "binary", "verbose": -1}, lgb.Dataset(X, label=y), 5), X


def test_measure_basic():
    scores = np.array([0.1, 0.6, 0.9, 0.4, 0.7, 0.95])
    y = np.array([0, 0, 0, 1, 1, 1])
    m = measure(scores, y, 0.5, pc_files=300)
    assert m["tpr"] == pytest.approx(2 / 3)
    assert m["fpr"] == pytest.approx(2 / 3)
    assert m["fp"] == 2
    assert m["expected_fp_pc"] == pytest.approx(200)


def test_measure_no_benign():
    scores = np.array([0.2, 0.8, 0.9])
    y = np.array([1, 1, 1])
    m = measure(scores, y, 0.5)
    assert m["tpr"] == pytest.approx(2 / 3)
    assert m["fpr"] is None
    assert m["fp"] is None
    assert m["expected_fp_pc"] is None


def test_per_week_splits_by_first_row():
    scores = np.array([0.9, 0.1, 0.9, 0.9, 0.1, 0.1])
    y = np.array([1, 0, 1, 1, 0, 0])
    meta = {"files": [{"file": "w0", "first_row": 0}, {"file": "w1", "first_row": 2}, {"file": "w2", "first_row": 4}]}
    weeks = per_week(scores, y, meta, 0.5)
    assert [w["file"] for w in weeks] == ["w0", "w1", "w2"]
    assert [w["n_benign"] + w["n_malicious"] for w in weeks] == [2, 2, 2]
    assert weeks[1]["fpr"] is None
    assert weeks[2]["tpr"] is None


def test_predict_chunks_matches_whole():
    booster, X = tiny_booster()
    whole = booster.predict(X)
    chunked = predict_chunks(booster, X, chunk=7)
    assert np.allclose(chunked, whole)


def test_load_checked_rejects_other_model(tmp_path):
    booster, _ = tiny_booster()
    model = tmp_path / "ember_win32.txt"
    booster.save_model(str(model))
    good = {"model_sha256": file_sha256(model)}
    (tmp_path / "thresholds.json").write_text(json.dumps(good), encoding="utf-8")
    load_checked(tmp_path)

    bad = {"model_sha256": "0" * 64}
    (tmp_path / "thresholds.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError):
        load_checked(tmp_path)