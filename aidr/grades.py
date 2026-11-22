"""판정 등급과 합치기 규칙."""

# 등급 순서: 숫자가 클수록 위험
ORDER = {"정상": 0, "검토 필요": 1, "의심": 2, "악성": 3}


def combine(fast_path_grade: str, ai_grade: str | None) -> str:
    """Fast path 등급과 AI 등급을 합친다.

    - AI는 등급을 올릴 수만 있고 내릴 수는 없다.
    - AI가 판정을 못 했으면(None) 최소 '검토 필요'.
    """
    if fast_path_grade not in ORDER:
        raise ValueError(f"알 수 없는 등급: {fast_path_grade}")
    if ai_grade is None:
        return max(fast_path_grade, "검토 필요", key=ORDER.get)
    if ai_grade not in ORDER:
        # 이상한 답은 믿지 않는다
        return max(fast_path_grade, "검토 필요", key=ORDER.get)
    return max(fast_path_grade, ai_grade, key=ORDER.get)