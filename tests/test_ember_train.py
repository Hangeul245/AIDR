import pytest

from aidr.ember_train import split_point


def fake_meta(weeks, rows_per_week=60000):
    files = [{"file": f"w{i}.jsonl", "first_row": i * rows_per_week} for i in range(weeks)]
    return {"files": files, "rows": weeks * rows_per_week}


def test_split_point():
    assert split_point(fake_meta(27), 4) == 1380000


@pytest.mark.parametrize("weeks, val_weeks", [(4, 4), (27, 0)])
def test_split_point_rejects(weeks, val_weeks):
    with pytest.raises(ValueError):
        split_point(fake_meta(weeks), val_weeks)