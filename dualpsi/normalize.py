"""명부 정규화와 매칭 키 (정규화 버전 kr-v1).

두 당이 같은 사람을 같은 문자열로 표현해야 교집합이 잡힌다. 규칙을 바꾸면 버전을 올리고,
양측 setup 메시지의 norm 설정이 같아야만 프로토콜이 진행된다.

매칭 등급(tier)
  strict(정밀): 이름 + 생년월일 + 휴대전화
  loose(후보) : 이름 + 생년월일  — 번호 변경자는 잡지만 동명이인이 섞이므로 확인 필요
"""

from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .util import lp

NORM_VERSION = "kr-v1"
TIERS = ("strict", "loose")
TIER_KO = {"strict": "정밀", "loose": "후보"}

_PAREN = re.compile(r"[\(\[\{].*?[\)\]\}]")


def norm_name(raw) -> str | None:
    """NFKC → 괄호 주석 제거 → 문자(L)·결합부호(M)만 유지 → 대문자. '홍 길동'·'홍길동(서울)' → '홍길동'."""
    s = unicodedata.normalize("NFKC", "" if raw is None else str(raw))
    s = _PAREN.sub("", s)
    s = "".join(ch for ch in s if unicodedata.category(ch)[0] in ("L", "M"))
    s = unicodedata.normalize("NFC", s).upper()
    return s or None


def default_pivot(today: _dt.date | None = None) -> int:
    """두 자리 연도 해석 기준. 입당 가능 연령(16세) 기준으로 (올해-16)의 끝 두 자리 이하면 2000년대."""
    today = today or _dt.date.today()
    return (today.year - 16) % 100


def _year2(yy: int, pivot: int) -> int:
    return (2000 if yy <= pivot else 1900) + yy


_CENTURY = {"1": 1900, "2": 1900, "5": 1900, "6": 1900, "3": 2000, "4": 2000, "7": 2000, "8": 2000}


def norm_birth(raw, pivot_yy: int) -> str | None:
    """여러 표기를 YYYYMMDD 로. 1980-01-02 / 19800102 / 1980.1.2 / 800102 / 80.01.02 /
    1980년 1월 2일 / 800102-1(성별자리, 뒷자리는 버림) 지원. 일·월 순서가 모호한 01/02/1980 은 거부."""
    s = unicodedata.normalize("NFKC", "" if raw is None else str(raw)).strip()
    if not s:
        return None
    s = re.split(r"[T\s]\d{1,2}:\d{2}", s, maxsplit=1)[0]  # '1980-01-02 00:00:00'
    g = re.findall(r"\d+", s)
    try:
        if len(g) == 1 and len(g[0]) == 8:
            y, m, d = int(g[0][:4]), int(g[0][4:6]), int(g[0][6:])
        elif len(g) == 1 and len(g[0]) == 6:
            y, m, d = _year2(int(g[0][:2]), pivot_yy), int(g[0][2:4]), int(g[0][4:])
        elif len(g) == 2 and len(g[0]) == 6 and len(g[1]) in (1, 7) and g[1][0] in _CENTURY:
            y, m, d = _CENTURY[g[1][0]] + int(g[0][:2]), int(g[0][2:4]), int(g[0][4:])
        elif len(g) == 3 and len(g[0]) in (2, 4) and len(g[1]) <= 2 and len(g[2]) <= 2:
            y = int(g[0]) if len(g[0]) == 4 else _year2(int(g[0]), pivot_yy)
            m, d = int(g[1]), int(g[2])
        else:
            return None
        _dt.date(y, m, d)
    except ValueError:
        return None
    if not 1900 <= y <= 2100:
        return None
    return f"{y:04d}{m:02d}{d:02d}"


def norm_phone(raw) -> str | None:
    """숫자만 남김. +82/82 국가번호 → 0, 엑셀이 앞자리 0을 지운 10자리 '10xxxxxxxx' 복원. 9~11자리만 인정."""
    s = unicodedata.normalize("NFKC", "" if raw is None else str(raw))
    d = re.sub(r"\D", "", s)
    if not d:
        return None
    if d.startswith("82") and len(d) >= 10:
        rest = d[2:]
        d = rest if rest.startswith("0") else "0" + rest
    elif len(d) == 10 and d.startswith("10"):
        d = "0" + d
    if not d.startswith("0") or not 9 <= len(d) <= 11:
        return None
    return d


@dataclass(frozen=True, order=True)
class Record:
    name: str
    birth: str
    phone: str = ""

    def to_bytes(self) -> bytes:
        return lp(NORM_VERSION, self.name, self.birth, self.phone)

    def key(self, tier: str) -> str | None:
        if tier == "strict":
            return f"{self.name}|{self.birth}|{self.phone}" if self.phone else None
        if tier == "loose":
            return f"{self.name}|{self.birth}"
        raise ValueError(f"알 수 없는 등급: {tier}")

    def as_dict(self) -> dict:
        return {"name": self.name, "birth": self.birth, "phone": self.phone}

    @classmethod
    def from_dict(cls, d: dict) -> "Record":
        return cls(str(d["name"]), str(d["birth"]), str(d.get("phone", "")))

    def is_normalized(self, pivot_yy: int) -> bool:
        return (norm_name(self.name) == self.name
                and norm_birth(self.birth, pivot_yy) == self.birth
                and (self.phone == "" or norm_phone(self.phone) == self.phone))


# ------------------------------------------------------------------ CSV 명부

_ALIASES = {
    "name": ["이름", "성명", "성함", "당원명", "회원명", "name", "fullname"],
    "birth": ["생년월일", "생일", "출생일", "출생년월일", "birth", "birthdate", "birthday", "dob", "dateofbirth"],
    "phone": ["휴대전화", "휴대전화번호", "휴대폰", "휴대폰번호", "핸드폰", "핸드폰번호", "휴대번호",
              "전화번호", "연락처", "전화", "phone", "mobile", "tel", "cellphone", "phonenumber"],
}


def _canon(h) -> str:
    return re.sub(r"[\s_\-\(\)\.]", "", unicodedata.normalize("NFKC", h or "")).lower()


@dataclass
class RosterData:
    path: Path
    sha256: str
    encoding: str
    columns: dict
    total_rows: int
    records: dict  # Record -> [CSV 줄 번호, ...]
    rejects: list  # [(줄 번호, 사유)]
    phone_missing: int


def read_text(path) -> tuple:
    data = Path(path).read_bytes()
    for enc in ("utf-8-sig", "cp949"):
        try:
            return data, data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise ValueError("인코딩을 알 수 없습니다 (UTF-8 또는 CP949/EUC-KR CSV만 지원)")


def detect_columns(fieldnames, overrides=None) -> dict:
    fieldnames = [f for f in fieldnames if f is not None]
    overrides = {k: v for k, v in (overrides or {}).items() if v}
    canon = {}
    for f in fieldnames:
        canon.setdefault(_canon(f), f)
    cols = {}
    for role in ("name", "birth", "phone"):
        if role in overrides:
            if overrides[role] not in fieldnames:
                raise ValueError(f"'{overrides[role]}' 열이 없습니다. 헤더: {fieldnames}")
            cols[role] = overrides[role]
            continue
        for alias in _ALIASES[role]:
            if _canon(alias) in canon:
                cols[role] = canon[_canon(alias)]
                break
    if "name" not in cols or "birth" not in cols:
        raise ValueError(f"이름/생년월일 열을 찾지 못했습니다. 헤더: {fieldnames} "
                         "(--col-name, --col-birth, --col-phone 으로 지정하세요)")
    return cols


def load_roster(path, pivot_yy: int, columns: dict | None = None) -> RosterData:
    data, text, enc = read_text(path)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        raise ValueError("CSV 헤더가 없습니다")
    cols = detect_columns(reader.fieldnames, columns)
    records: dict = {}
    rejects: list = []
    total = phone_missing = 0
    for row in reader:
        total += 1
        line = reader.line_num
        name = norm_name(row.get(cols["name"]))
        if not name:
            rejects.append((line, "이름 인식 불가"))
            continue
        birth = norm_birth(row.get(cols["birth"]), pivot_yy)
        if not birth:
            rejects.append((line, "생년월일 인식 불가"))
            continue
        phone = norm_phone(row.get(cols["phone"])) if "phone" in cols else None
        if not phone:
            phone_missing += 1
        records.setdefault(Record(name, birth, phone or ""), []).append(line)
    return RosterData(Path(path), hashlib.sha256(data).hexdigest(), enc, cols, total, records, rejects, phone_missing)
