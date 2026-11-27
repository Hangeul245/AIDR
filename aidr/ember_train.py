import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np

from aidr.ember_prep import read_subset

def split_point(meta, val_weeks=4):
    files = meta["files"]
    if val_weeks < 1:
        raise ValueError("val_week는 1 이상")
    if len(files) <= val_weeks:
        raise ValueError(f"학습할 주가 없음")
    s = files[-val_weeks]["first_row"]
    if s == 0 or s >= meta["rows"]:
        raise ValueError(f"경계 행 {s}가 잘못됨 (전체 {meta['rows']}행)")
    return s

def load_split(vec_dir, val_weeks=4):
    X, y, meta = read_subset(vec_dir, "train")
    s = split_point(meta, val_weeks)
    X_tr, y_tr = X[:s], y[:s]
    X_va, y_va = X[s:], y[s:]
    for name, part in (("학습", y_tr), ("검증", y_va)):
        if not np.array_equal(np.unique(part), [0, 1]):
            raise ValueError(f"{name} 라벨이 한쪽뿐임: {np.unique(part)}")
    return X_tr, y_tr, X_va, y_va, s

def make_params(seed, threads):
    return {
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 255,
        "min_data_in_leaf": 50,
        "feature_fraction": 0.5,
        "bagging_fraction": 0.8,
        "bagging_freq": 1,
        "seed": seed,
        "num_threads": threads,
        "verbose": -1,
    }

def train_model(X_tr, y_tr, X_va, y_va, params, rounds, stop):
    train_set = lgb.Dataset(X_tr, label= y_tr, free_raw_data=True)
    valid_set = lgb.Dataset(X_va, label = y_va, reference= train_set, free_raw_data=True)
    booster = lgb.train(
        params,
        train_set,
        num_boost_round= rounds,
        valid_sets = [valid_set],
        valid_names = ["val"],
        callbacks= [lgb.early_stopping(stop), lgb.log_evaluation(50)]
    )
    return booster

def save_outputs(booster, out_dir, scores, y_va, info):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model_path = out_dir / "ember_win32.txt"
    tmp = model_path.with_name(model_path.name + ".tmp")
    booster.save_model(str(tmp), num_iteration= booster.best_iteration)
    os.replace(tmp, model_path)

    val_path = out_dir / "val_scores.npz"
    tmp = val_path.with_name(val_path.name + ".tmp")
    with open(tmp, "wb") as f:
        np.savez(f, scores = scores, y= y_va)
    os.replace(tmp, val_path)

    meta_path = out_dir / "train_meta.json"
    tmp = meta_path.with_name(meta_path.name + ".tmp")
    tmp.write_text(
        json.dumps(info, ensure_ascii=False, indent=2), 
        encoding= "utf-8"
    )
    os.replace(tmp, meta_path)

def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m aidr.ember_train")
    ap.add_argument("vec_dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--val-weeks", type=int, default=4)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--stop", type=int, default=50)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--threads", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    args = ap.parse_args(argv)

    X_tr, y_tr, X_va, y_va, s = load_split(args.vec_dir, args.val_weeks)
    print(f"학습 {len(y_tr)}행, 검증 {len(y_va)}행 (경계 {s})")

    params = make_params(args.seed, args.threads)
    t0 = time.time()
    booster = train_model(X_tr, y_tr, X_va, y_va, params, args.rounds, args.stop)
    seconds = time.time() - t0

    scores = booster.predict(X_va, num_iteration=booster.best_iteration)
    info = {
        "split_row": int(s),
        "rows_train": int(len(y_tr)),
        "rows_val": int(len(y_va)),
        "best_iteration": int(booster.best_iteration),
        "val_auc": float(booster.best_score["val"]["auc"]),
        "params": params,
        "lightgbm": lgb.__version__,
        "seconds": round(seconds, 1),
        "created": datetime.now().isoformat(timespec="seconds"),
    }
    save_outputs(booster, args.out, scores, y_va, info)
    print(f"완료: 나무 {info['best_iteration']}개, 검증 AUC {info['val_auc']:.5f}, {seconds / 60:.1f}분")


if __name__ == "__main__":
    main()

   