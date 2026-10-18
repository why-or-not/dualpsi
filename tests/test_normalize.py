import pytest

from dualpsi.normalize import Record, detect_columns, load_roster, norm_birth, norm_name, norm_phone

P = 10  # 2026년 기준 기본값: 00~10 → 2000년대


@pytest.mark.parametrize("raw,exp", [
    ("홍길동", "홍길동"), (" 홍 길동 ", "홍길동"), ("홍길동(서울)", "홍길동"), ("남궁 민수", "남궁민수"),
    ("Kim Min-su", "KIMMINSU"), ("ＫＩＭ", "KIM"), ("홍길동", "홍길동"),
    ("", None), (None, None), ("123", None),
])
def test_name(raw, exp):
    assert norm_name(raw) == exp


@pytest.mark.parametrize("raw,exp", [
    ("1980-01-02", "19800102"), ("19800102", "19800102"), ("1980.1.2", "19800102"), ("800102", "19800102"),
    ("80.01.02", "19800102"), ("1980년 1월 2일", "19800102"), ("800102-1", "19800102"),
    ("050315-3", "20050315"), ("1980-01-02 00:00:00", "19800102"), ("100101", "20100101"),
    ("110101", "19110101"), ("01/02/1980", None), ("1980-02-30", None), ("미상", None), ("", None),
])
def test_birth(raw, exp):
    assert norm_birth(raw, P) == exp


@pytest.mark.parametrize("raw,exp", [
    ("010-1234-5678", "01012345678"), ("01012345678", "01012345678"), ("+82 10-1234-5678", "01012345678"),
    ("+82 (0)10-1234-5678", "01012345678"), ("1012345678", "01012345678"), ("010 1234 5678", "01012345678"),
    ("02-123-4567", "021234567"), ("82-2-123-4567", "021234567"),
    ("010-1111-2222 / 010-3333-4444", None), ("없음", None), ("212345678", None),
])
def test_phone(raw, exp):
    assert norm_phone(raw) == exp


def test_keys():
    r = Record("홍길동", "19800102", "01011112222")
    assert r.key("strict") == "홍길동|19800102|01011112222"
    assert r.key("loose") == "홍길동|19800102"
    assert Record("홍길동", "19800102").key("strict") is None
    assert r.is_normalized(P) and not Record("홍 길동", "19800102").is_normalized(P)


def test_detect_columns():
    assert detect_columns(["성명", "생 년 월 일", "연락처"]) == {"name": "성명", "birth": "생 년 월 일", "phone": "연락처"}
    assert detect_columns(["Name", "DOB"]) == {"name": "Name", "birth": "DOB"}
    with pytest.raises(ValueError):
        detect_columns(["주소", "직업"])
    assert detect_columns(["a", "b", "c"], {"name": "a", "birth": "b", "phone": "c"})["phone"] == "c"


def test_load_cp949_dedup_and_rejects(tmp_path):
    p = tmp_path / "r.csv"
    text = "성명,생일,휴대폰\n홍길동,800102,010-1111-2222\n홍 길동,1980.1.2,+82 10 1111 2222\n김미상,미상,\n이영희,1990-12-31,\n"
    p.write_bytes(text.encode("cp949"))
    rd = load_roster(p, P)
    assert rd.encoding == "cp949"
    assert rd.total_rows == 4 and len(rd.rejects) == 1 and rd.rejects[0][0] == 4
    assert len(rd.records) == 2  # 홍길동 두 줄은 한 사람으로 병합
    assert rd.records[Record("홍길동", "19800102", "01011112222")] == [2, 3]
    assert rd.phone_missing == 1
