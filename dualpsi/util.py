"""공용 유틸리티: 모호성 없는 직렬화, 해시, PRF, 비밀 파일 저장."""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
from pathlib import Path


def lp(*parts) -> bytes:
    """길이 접두 직렬화. 각 필드를 (8바이트 길이 || 값)으로 이어 붙여 경계 모호성을 없앤다."""
    out = bytearray()
    for p in parts:
        if isinstance(p, bool):
            raise TypeError("bool은 직렬화하지 않습니다")
        if isinstance(p, str):
            p = p.encode("utf-8")
        elif isinstance(p, int):
            if p < 0:
                raise ValueError("음수 정수는 직렬화하지 않습니다")
            p = p.to_bytes(8, "big")
        elif isinstance(p, (bytearray, memoryview)):
            p = bytes(p)
        elif not isinstance(p, bytes):
            raise TypeError(f"직렬화할 수 없는 타입: {type(p).__name__}")
        out += len(p).to_bytes(8, "big")
        out += p
    return bytes(out)


def unlp(data: bytes) -> list:
    """lp() 의 역. 형식이 어긋나면 ValueError."""
    out, i = [], 0
    while i < len(data):
        if i + 8 > len(data):
            raise ValueError("잘린 직렬화 데이터")
        n = int.from_bytes(data[i : i + 8], "big")
        i += 8
        if i + n > len(data):
            raise ValueError("잘린 직렬화 데이터")
        out.append(data[i : i + n])
        i += n
    return out


def H(*parts) -> bytes:
    """도메인 분리된 SHA-256."""
    return hashlib.sha256(lp(*parts)).digest()


def prf(key: bytes, *parts) -> bytes:
    """HMAC-SHA256 기반 PRF. 비밀 시드로부터 결정론적 값을 유도할 때 쓴다."""
    return hmac.new(key, lp(*parts), hashlib.sha256).digest()


def cjson(obj) -> bytes:
    """정규(canonical) JSON 직렬화 — 서명·해시 대상."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(pk: bytes) -> str:
    """서명 공개키 지문. 상대와 전화·서면으로 대조하는 용도."""
    h = hashlib.sha256(b"dualpsi/v1/fp" + pk).hexdigest()[:24].upper()
    return " ".join(h[i : i + 4] for i in range(0, 24, 4))


def fp_normalize(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch in "0123456789ABCDEF")


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def write_private_bytes(path: Path, data: bytes) -> None:
    """소유자만 읽을 수 있는 권한(0600)으로 원자적 저장."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def write_private_json(path: Path, obj) -> None:
    write_private_bytes(path, json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"))
