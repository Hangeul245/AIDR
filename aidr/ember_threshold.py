import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

import numpy as np

LEVELS = {
        "service": 0.0001, 
        "suspicious": 0.001, 
        "research": 0.01,
}

def pick_threshold(benign, fpr):
    n= len(benign)
    if n == 0:
         raise ValueError("정상 점수가 없음")
    if not 0 < fpr < 1:
        raise ValueError(f"오탐률 {fpr}는 0과 1 사이여야 함")
    k = int(n * fpr + 1e-9)
    desc = np.sort(benign)[ : : -1]
    return float(desc[k]), k

def rates(scores, y, thr):
    pred = scores > thr

    fpr = (pred[y == 0]).mean()
    tpr = (pred[y == 1]).mean()

    return float(fpr), float(tpr)

def compute_thresholds(scores, y):
    scores = np.asarray(scores)
    y = np.asarray(y)
    if len(scores) != len(y):
        raise ValueError(f"점수 {len(scores)}개, 라벨 {len(y)}개로 다름")
    benign = scores[y == 0]
    n_mal = int((y == 1).sum())
    if n_mal == 0:
        raise ValueError("악성 점수가 없음")

    levels = {}
    for name, fpr in LEVELS.items():
        thr, k = pick_threshold(benign, fpr)
        val_fpr, val_tpr = rates(scores, y, thr)
        levels[name] = {
            "target_fpr": fpr,
            "threshold": thr,
            "allowed_fp": k,
            "val_fpr": val_fpr,
            "val_tpr": val_tpr,
        }
    return {"n_benign": int(len(benign)), "n_malicious": n_mal, "levels": levels}

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m aidr.ember_threshold")
    ap.add_argument("models_dir")
    args = ap.parse_args(argv)

    d = Path(args.models_dir)
    train_meta = json.loads((d / "train_meta.json").read_text(encoding="utf-8"))
    with np.load(d / "val_scores.npz") as z:
        scores, y = z["scores"], z["y"]

    result = compute_thresholds(scores, y)
    result["rule"] = "score > threshold"
    result["model_sha256"] = file_sha256(d / "ember_win32.txt")
    result["model_created"] = train_meta["created"]
    result["best_iteration"] = train_meta["best_iteration"]
    result["created"] = datetime.now().isoformat(timespec="seconds")

    out = d / "thresholds.json"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, out)

    for name, lv in result["levels"].items():
        print(f"{name}: 오탐 {lv['val_fpr']:.4%} (허용 {lv['allowed_fp']}개), 탐지 {lv['val_tpr']:.2%}")


if __name__ == "__main__":
    main()
