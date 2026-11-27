import argparse
import json
import os
from datetime import datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np

from aidr.ember_prep import read_subset
from aidr.ember_threshold import file_sha256

SUBSETS = ("test", "challenge")


def load_checked(models_dir):
    d = Path(models_dir)
    model_path = d / "ember_win32.txt"
    thresholds = json.loads((d / "thresholds.json").read_text(encoding="utf-8"))
    if file_sha256(model_path) != thresholds["model_sha256"]:
        raise ValueError("모델 파일이 thresholds.json을 만든 모델과 다름. 임계값을 다시 계산할 것")
    booster = lgb.Booster(model_file=str(model_path))
    return booster, thresholds


def predict_chunks(booster, X, chunk=50000):
    out = np.empty(len(X), dtype=np.float64)
    for i in range(0, len(X), chunk):
        out[i:i + chunk] = booster.predict(X[i:i + chunk])
    return out


def measure(scores, y, thr, pc_files=20000):
    pred = scores > thr
    benign = pred[y == 0]
    malicious = pred[y == 1]
    result = {"n_benign": int(len(benign)), "n_malicious": int(len(malicious))}
    if len(malicious) > 0:
        result["tpr"] = float(malicious.mean())
    else:
        result["tpr"] = None
    if len(benign) > 0:
        fpr = float(benign.mean())
        result["fpr"] = fpr
        result["fp"] = int(benign.sum())
        result["expected_fp_pc"] = round(fpr * pc_files, 2)
    else:
        result["fpr"] = None
        result["fp"] = None
        result["expected_fp_pc"] = None
    return result


def per_week(scores, y, meta, thr):
    files = meta["files"]
    weeks = []
    for i, f in enumerate(files):
        start = f["first_row"]
        end = files[i + 1]["first_row"] if i + 1 < len(files) else len(scores)
        r = measure(scores[start:end], y[start:end], thr)
        r["file"] = f["file"]
        weeks.append(r)
    return weeks


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m aidr.ember_eval")
    ap.add_argument("vec_dir")
    ap.add_argument("models_dir")
    args = ap.parse_args(argv)

    booster, thresholds = load_checked(args.models_dir)
    levels = thresholds["levels"]

    report = {
        "model_sha256": thresholds["model_sha256"],
        "rule": thresholds["rule"],
        "subsets": {},
        "created": datetime.now().isoformat(timespec="seconds"),
    }
    for subset in SUBSETS:
        X, y, meta = read_subset(args.vec_dir, subset)
        scores = predict_chunks(booster, X)
        sub = {}
        for name, lv in levels.items():
            sub[name] = measure(scores, y, lv["threshold"])
        if subset == "test":
            sub["weekly_service"] = per_week(scores, y, meta, levels["service"]["threshold"])
        report["subsets"][subset] = sub

        for name in levels:
            m = sub[name]
            line = f"[{subset}] {name}: 탐지 {m['tpr']:.2%}"
            if m["fpr"] is not None:
                line += f", 오탐 {m['fpr']:.4%} ({m['fp']}개), PC 한 대 예상 오탐 {m['expected_fp_pc']}개"
            print(line)

    out = Path(args.models_dir) / "eval.json"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, out)


if __name__ == "__main__":
    main()