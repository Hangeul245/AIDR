"""정상 기준선(SysWOW64, 서드파티)을 모델로 채점해 임계값별 오탐을 잰다.

python -m aidr.baseline_eval <특징.jsonl> <모델 폴더> --name <기준선 이름>

- 입력은 python -m aidr features 가 만든 JSONL (정상 파일만)
- 32비트(I386)만 채점한다. 모델이 Win32 학습 데이터로 만들어졌기 때문. 나머지는 개수만 센다
- 오탐 파일은 이름만 남긴다 (경로 없음)
- 임계값 숫자는 화면에 찍지 않는다
- 결과는 모델 폴더(저장소 바깥)에 baseline_<이름>.json
"""
import argparse
import json
import os
from datetime import datetime
from pathlib import Path

import numpy as np

from aidr.ember_eval import load_checked, measure

I386 = "IMAGE_FILE_MACHINE_I386"


def read_rows(path):
    """JSONL을 dict 목록으로. JSON이 아닌 줄은 개수만 센다."""
    rows, bad = [], 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            bad += 1
    return rows, bad


def split_by_machine(rows):
    """32비트(I386)만 남기고, 나머지는 machine 값별 개수로 돌려준다."""
    keep, skipped = [], {}
    for row in rows:
        machine = row.get("header", {}).get("coff", {}).get("machine", "?")
        if machine == I386:
            keep.append(row)
        else:
            skipped[machine] = skipped.get(machine, 0) + 1
    return keep, skipped


def vectorize(rows, extractor):
    """raw 특징 → 학습 때와 같은 숫자 벡터. 실패한 파일은 이름과 이유를 남긴다 (조용히 빠지지 않게)."""
    vecs, names, failed = [], [], []
    for row in rows:
        name = row.get("file_name", "?")
        try:
            vec = np.asarray(extractor.process_raw_features(row), dtype=np.float32)
        except Exception as e:  # 외부 라이브러리가 어떤 예외를 낼지 모름
            failed.append([name, f"특징 계산 실패: {type(e).__name__}"])
            continue
        if vec.shape != (extractor.dim,):
            failed.append([name, f"특징 길이 {vec.shape}"])
            continue
        vecs.append(vec)
        names.append(name)
    X = np.vstack(vecs) if vecs else np.empty((0, extractor.dim), dtype=np.float32)
    return X, names, failed


def evaluate(scores, names, levels):
    """단계별 오탐률, 오탐 개수, PC 한 대 예상 오탐 수, 오탐 파일 이름."""
    y = np.zeros(len(scores), dtype=np.int8)  # 기준선은 전부 정상
    result = {}
    for level, info in levels.items():
        thr = info["threshold"]
        m = measure(scores, y, thr)
        m["fp_files"] = sorted(n for n, s in zip(names, scores) if s > thr)  # 판정 규칙과 같은 초과(>)
        result[level] = m
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m aidr.baseline_eval")
    ap.add_argument("features_jsonl")
    ap.add_argument("models_dir")
    ap.add_argument("--name", required=True, help="기준선 이름 (예: syswow64, thirdparty)")
    args = ap.parse_args(argv)

    booster, thresholds = load_checked(args.models_dir)
    rows, bad = read_rows(args.features_jsonl)
    keep, skipped = split_by_machine(rows)

    import thrember  # 무거워서 실제로 쓸 때만 불러온다
    X, names, failed = vectorize(keep, thrember.PEFeatureExtractor())
    if not names:
        raise SystemExit("채점할 32비트 파일이 없음")

    scores = np.asarray(booster.predict(X), dtype=np.float64)
    levels = evaluate(scores, names, thresholds["levels"])

    report = {
        "baseline": args.name,
        "model_sha256": thresholds["model_sha256"],
        "rule": thresholds["rule"],
        "rows": len(rows),
        "bad_json": bad,
        "skipped_machine": skipped,
        "vectorize_failed": failed,
        "scored": len(names),
        "levels": levels,
        "created": datetime.now().isoformat(timespec="seconds"),
    }

    print(f"[{args.name}] 전체 {len(rows)}개, 32비트 채점 {len(names)}개, "
          f"다른 형식 건너뜀 {sum(skipped.values())}개 {skipped}, 특징 계산 실패 {len(failed)}개, JSON 아님 {bad}개")
    for level, m in levels.items():
        print(f"  {level}: 오탐 {m['fpr']:.4%} ({m['fp']}개), PC 한 대 예상 오탐 {m['expected_fp_pc']}개")
        for name in m["fp_files"][:10]:
            print(f"    - {name}")

    out = Path(args.models_dir) / f"baseline_{args.name}.json"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, out)
    print(f"저장 → {out}")


if __name__ == "__main__":
    main()
