from pathlib import Path

import yara

# 규칙 meta에 severity가 없으면 약한 신호로 취급한다 (오탐을 줄이는 쪽)
DEFAULT_SEVERITY = "low"


def load_rules(path):
    """규칙 파일을 컴파일해서 돌려준다. 문법 오류면 yara.SyntaxError가 난다."""
    return yara.compile(filepath=str(path))


def match_file(rules, path, timeout=10):
    """걸린 규칙을 [(규칙 이름, 심각도), ...]로 돌려준다.

    경로를 YARA에 직접 넘기면 Windows에서 한글 경로를 못 연다.
    그래서 Python이 바이트로 읽고 내용(data)을 넘긴다.
    시간 초과(yara.TimeoutError)나 오류(yara.Error, OSError)는
    부르는 쪽(scanner)으로 올린다. 그쪽에서 '검토 필요'로 처리한다.
    """
    data = Path(path).read_bytes()
    matches = rules.match(data=data, timeout=timeout)
    return [(m.rule, m.meta.get("severity", DEFAULT_SEVERITY)) for m in matches]



def test_korean_path_matches(tmp_path):
    rules = make_rules(tmp_path)
    target = tmp_path / "한글문서.bin"
    target.write_bytes(b"AIDR_STRONG_MARKER")
    assert match_file(rules, target) == [("Strong_Marker", "high")]