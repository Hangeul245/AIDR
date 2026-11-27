import hashlib
import json

import numpy as np
import pytest

from aidr.ember_threshold import compute_thresholds, main, pick_threshold, rates


def test_pick_threshold_basic():
    benign = np.array([0.1, 0.9, 0.5, 0.3, 0.7, 0.2, 0.8, 0.4, 0.6, 1.0])
    thr, k = pick_threshold(benign, 0.2)
    assert k == 2
    assert thr == 0.8
    assert (benign > thr).sum() == k


def test_pick_threshold_k_zero():
    benign = np.array([0.1, 0.5, 0.9])
    thr, k = pick_threshold(benign, 0.1)
    assert k == 0
    assert thr == 0.9
    assert (benign > thr).sum() == 0


def test_pick_threshold_ties():
    benign = np.array([0.9, 0.9, 0.9, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    thr, k = pick_threshold(benign, 0.1)
    assert k == 1
    assert (benign > thr).sum() <= k


@pytest.mark.parametrize("benign, fpr", [
    (np.array([]), 0.01),
    (np.array([0.1, 0.2]), 0.0),
    (np.array([0.1, 0.2]), 1.0),
])
def test_pick_threshold_rejects(benign, fpr):
    with pytest.raises(ValueError):
        pick_threshold(benign, fpr)


def test_rates():
    scores = np.array([0.1, 0.6, 0.9, 0.4, 0.7, 0.95])
    y = np.array([0, 0, 0, 1, 1, 1])
    fpr, tpr = rates(scores, y, 0.5)
    assert fpr == pytest.approx(2 / 3)
    assert tpr == pytest.approx(2 / 3)


def test_compute_thresholds_levels():
    rng = np.random.default_rng(0)
    benign = rng.random(10000)
    malicious = rng.random(1000) + 0.5
    scores = np.concatenate([benign, malicious])
    y = np.concatenate([np.zeros(10000, dtype=np.int32), np.ones(1000, dtype=np.int32)])

    r = compute_thresholds(scores, y)
    assert r["n_benign"] == 10000
    assert r["n_malicious"] == 1000
    expected_k = {"service": 1, "suspicious": 10, "research": 100}
    for name, lv in r["levels"].items():
        assert lv["allowed_fp"] == expected_k[name]
        assert lv["val_fpr"] <= lv["target_fpr"]
    assert r["levels"]["service"]["threshold"] >= r["levels"]["research"]["threshold"]


@pytest.mark.parametrize("scores, y", [
    ([0.1, 0.2, 0.3], [0, 1]),
    ([0.1, 0.2, 0.3], [0, 0, 0]),
])
def test_compute_thresholds_rejects(scores, y):
    with pytest.raises(ValueError):
        compute_thresholds(scores, y)


def test_main_writes_json(tmp_path):
    rng = np.random.default_rng(1)
    scores = np.concatenate([rng.random(10000), rng.random(1000) + 0.5])
    y = np.concatenate([np.zeros(10000, dtype=np.int32), np.ones(1000, dtype=np.int32)])
    with open(tmp_path / "val_scores.npz", "wb") as f:
        np.savez(f, scores=scores, y=y)
    (tmp_path / "train_meta.json").write_text(
        json.dumps({"created": "2026-11-27T13:00:00", "best_iteration": 1950}),
    )