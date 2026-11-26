from datetime import date
from pathlib import Path
SUBSETS = ("train", "test", "challenge")


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

    

   

    









    

