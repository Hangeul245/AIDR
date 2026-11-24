from aidr.yara_scan import load_rules, match_file

RULES = '''
rule Strong_Marker
{
    meta:
        severity = "high"
    strings:
        $s = "AIDR_STRONG_MARKER"
    condition:
        $s
}

rule No_Severity
{
    strings:
        $s = "AIDR_PLAIN_MARKER"
    condition:
        $s
}
'''


def make_rules(tmp_path):
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(RULES, encoding="utf-8")
    return load_rules(rule_file)


def test_high_rule_matches(tmp_path):
    rules = make_rules(tmp_path)
    target = tmp_path / "a.bin"
    target.write_bytes(b"xx AIDR_STRONG_MARKER xx")
    assert match_file(rules, target) == [("Strong_Marker", "high")]


def test_clean_file_has_no_match(tmp_path):
    rules = make_rules(tmp_path)
    target = tmp_path / "clean.bin"
    target.write_bytes(b"nothing here")
    assert match_file(rules, target) == []


def test_missing_severity_is_low(tmp_path):
    rules = make_rules(tmp_path)
    target = tmp_path / "b.bin"
    target.write_bytes(b"AIDR_PLAIN_MARKER")
    assert match_file(rules, target) == [("No_Severity", "low")]

def test_korean_path_matches(tmp_path):
    rules = make_rules(tmp_path)
    target = tmp_path / "한글문서.bin"
    target.write_bytes(b"AIDR_STRONG_MARKER")
    assert match_file(rules, target) == [("Strong_Marker", "high")]