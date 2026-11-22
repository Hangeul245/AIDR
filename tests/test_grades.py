import pytest

from aidr.grades import combine


def test_ai_can_raise_grade():
    assert combine("정상", "의심") == "의심"


def test_ai_cannot_lower_grade():
    # 인젝션에 속은 AI가 '정상'이라고 해도 내려가면 안 된다
    assert combine("의심", "정상") == "의심"
    assert combine("악성", "정상") == "악성"


def test_ai_failure_is_never_normal():
    # LLM이 꺼지거나 판정을 못 하면 절대 정상이 아니다 (11/18 버그)
    assert combine("정상", None) == "검토 필요"


def test_weird_ai_answer_is_not_trusted():
    assert combine("정상", "아마 괜찮음") == "검토 필요"


def test_unknown_fast_path_grade_raises():
    with pytest.raises(ValueError):
        combine("몰라", "정상")