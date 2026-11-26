import json
import multiprocessing
import os
import sys
import time
from datetime import date
from functools import partial
from pathlib import Path

import numpy as np

SUBSETS = ("train", "test", "challenge")
_extractor = None

def vectorize_line(line, require_type=False):
    try:
        raw = json.loads(line)
    except ValueError:
        return "fail", "JSON 아님", None
    if not isinstance(raw, dict):
        return "fail", "JSON 객체 아님", None

    ftype = raw.get("file_type")
    if ftype is None:
        if require_type:
            return "other", "file_type 없음", None
    elif ftype.lower() != "win32":
        return "other", ftype, None

    label = raw.get("label")
    if isinstance(label, bool) or label not in (0, 1):
        return "nolabel", None, None

    try:
        vec = np.asarray(_extractor.process_raw_features(raw), dtype=np.float32)
    except Exception as e:
        return "fail", f"특징 계산 실패: {type(e).__name__}", None
    if vec.shape != (_extractor.dim,):
        return "fail", f"특징 길이 {vec.shape}", None
    return "ok", vec.tobytes(), int(label)

def _init_worker():
    global _extractor
    import thrember
    _extractor = thrember.PEFeatureExtractor()

def vectorize_subset(files, out_dir, name,      processes=None, require_type=False):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    x_path = out_dir / f"X_{name}.dat"
    y_path = out_dir / f"y_{name}.dat"
    meta_path = out_dir / f"{name}_meta.json"
    x_tmp = out_dir / f"X_{name}.dat.tmp"

    func = partial(vectorize_line, require_type=require_type)
    if processes == 0:
        _init_worker()
        pool = None
        mapper = lambda lines: map(func, lines)
    else:
        pool = multiprocessing.Pool(processes=processes, initializer=_init_worker)
        mapper = lambda lines: pool.imap(func, lines, chunksize=16)
        labels, file_stats, failures = [], [], []
    try:
        with x_tmp.open("wb") as xf:
            for path in files:
                st = {"file": path.name, "first_row": len(labels),
                      "ok": 0, "nolabel": 0, "other": 0, "fail": 0, "other_types": {}}
                with path.open("r", encoding="utf-8") as f:
                    for lineno, (status, value, label) in enumerate(mapper(f), start=1):
                        st[status] += 1
                        if status == "ok":
                            xf.write(value)
                            labels.append(label)
                        elif status == "other":
                            st["other_types"][value] = st["other_types"].get(value, 0) + 1
                        elif status == "fail" and len(failures) < 50:
                            failures.append({"file": path.name, "line": lineno, "error": value})
                file_stats.append(st)
                print(f"  {path.name}: 저장 {st['ok']}, 라벨 없음 {st['nolabel']}, "
                      f"다른 형식 {st['other']}, 실패 {st['fail']}", flush=True)
    finally:
        if pool is not None:
            pool.close()
            pool.join()
        y = np.asarray(labels, dtype=np.int32)
    y_tmp = out_dir / f"y_{name}.dat.tmp"
    y.tofile(y_tmp)

    totals = {k: sum(s[k] for s in file_stats) for k in ("ok", "nolabel", "other", "fail")}
    meta = {
        "name": name,
        "rows": int(len(y)),
        "dim": feature_dim(),
        "malicious": int((y == 1).sum()),
        "benign": int((y == 0).sum()),
        "totals": totals,
        "files": file_stats,
        "failures_first": failures,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    os.replace(x_tmp, x_path)
    os.replace(y_tmp, y_path)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return meta


def feature_dim():
    import thrember
    return int(thrember.PEFeatureExtractor().dim)

def parse_name(name):
    if not name.endswith(".jsonl"):
        return None
    parts = name.removesuffix(".jsonl").split("_")
    if len(parts) != 4:
        return None
    try:
        start = date.fromisoformat(parts[0])
        date.fromisoformat(parts[1])
    except ValueError:
        return None
    if parts[3] in ("train", "test"):
        return start, parts[2], parts[3]
    if parts[2] == "challenge":
        return start, None, "challenge"
    return None

def list_files(data_dir, subset):
    if subset not in SUBSETS:
        raise ValueError(f"Unknown set: {subset}")
    picked = []
    
    for p in Path(data_dir).glob("*.jsonl"):
        info = parse_name(p.name)
        if info == None:
            continue
        start, ftype, sub = info

        if sub != subset:
            continue
        
        if subset != "challenge" and ftype != "Win32":
            continue

        picked.append((start, p))
    picked.sort()
    return [p for start, p in picked]

def read_subset(out_dir, name):
    out_dir = Path(out_dir)
    meta = json.loads((out_dir / f"{name}_meta.json").read_text(encoding="utf-8"))
    n, dim = meta["rows"], meta["dim"]
    X = np.memmap(out_dir / f"X_{name}.dat", dtype=np.float32, mode="r", shape=(n, dim))
    y = np.fromfile(out_dir / f"y_{name}.dat", dtype=np.int32)
    if len(y) != n:
        raise ValueError(f"{name}: 메타는 {n}행인데 라벨은 {len(y)}개")
    return X, y, meta

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="python -m aidr.ember_prep")
    ap.add_argument("data_dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--subset", choices=SUBSETS + ("all",), default="all")
    ap.add_argument("--processes", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    args = ap.parse_args(argv)

    subsets = SUBSETS if args.subset == "all" else (args.subset,)
    for subset in subsets:
        files = list_files(args.data_dir, subset)
        if not files:
            print(f"{subset}: 파일 없음", file=sys.stderr)
            return 1
        print(f"[{subset}] 파일 {len(files)}개 시작 (프로세스 {args.processes}개)", flush=True)
        meta = vectorize_subset(files, args.out, subset, processes=args.processes,
                                require_type=(subset == "challenge"))
        t = meta["totals"]
        print(f"[{subset}] 완료: 저장 {t['ok']}행 (악성 {meta['malicious']}, 정상 {meta['benign']}), "
              f"라벨 없음 {t['nolabel']}, 다른 형식 {t['other']}, 실패 {t['fail']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

    

   

    









    

