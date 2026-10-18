"""서명된 프로토콜 메시지 컨테이너.

형식: MAGIC(8) || 헤더 길이(4, big-endian) || 정규 JSON 헤더 || 페이로드(32바이트 점들)
헤더에는 페이로드 SHA-256과 Ed25519 서명이 들어간다. 모든 메시지가 서명되므로
나중에 감사·분쟁에서 "누가 무엇을 보냈는지"를 부인할 수 없다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .util import cjson

MAGIC = b"DUALPSI1"


class MessageError(Exception):
    """메시지 형식·서명 오류."""


@dataclass
class Msg:
    path: Path | None
    header: dict
    payload: bytes
    raw: bytes
    header_bytes: bytes

    @property
    def msg_id(self) -> bytes:
        """메시지 식별자. 헤더(페이로드 해시·서명 포함)의 해시이므로 메시지 전체에 바인딩된다."""
        return hashlib.sha256(b"dualpsi/v1/msg" + self.header_bytes).digest()

    @property
    def pk(self) -> bytes:
        return bytes.fromhex(self.header["sig_pk"])

    @property
    def type(self) -> str:
        return self.header.get("type", "")


def _sign_body(header: dict, sk: SigningKey) -> dict:
    h = dict(header)
    h.pop("sig", None)
    h["sig_pk"] = sk.verify_key.encode().hex()
    h["sig"] = sk.sign(cjson(h)).signature.hex()
    return h


def write_msg(path: Path, header: dict, payload: bytes, sk: SigningKey) -> Msg:
    h = dict(header)
    h["payload_len"] = len(payload)
    h["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    h = _sign_body(h, sk)
    hb = cjson(h)
    raw = MAGIC + len(hb).to_bytes(4, "big") + hb + payload
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(raw)
    tmp.replace(path)
    return Msg(path, h, payload, raw, hb)


def parse_msg(raw: bytes, path: Path | None = None, expect_type: str | None = None,
              expect_pk: bytes | None = None) -> Msg:
    where = f" ({path})" if path else ""
    if not raw.startswith(MAGIC) or len(raw) < 12:
        raise MessageError(f"dualpsi 메시지가 아닙니다{where}")
    hl = int.from_bytes(raw[8:12], "big")
    hb = raw[12 : 12 + hl]
    payload = raw[12 + hl :]
    try:
        header = json.loads(hb.decode("utf-8"))
    except Exception as e:
        raise MessageError(f"헤더를 읽을 수 없습니다{where}") from e
    if cjson(header) != hb:
        raise MessageError(f"비정규 헤더{where}")
    try:
        sig = bytes.fromhex(header["sig"])
        pk = bytes.fromhex(header["sig_pk"])
        body = {k: v for k, v in header.items() if k != "sig"}
        VerifyKey(pk).verify(cjson(body), sig)
    except (KeyError, ValueError, BadSignatureError) as e:
        raise MessageError(f"서명 검증 실패{where}") from e
    if header.get("payload_len") != len(payload) or header.get("payload_sha256") != hashlib.sha256(payload).hexdigest():
        raise MessageError(f"페이로드 무결성 검증 실패{where}")
    if expect_type is not None and header.get("type") != expect_type:
        raise MessageError(f"메시지 종류가 {expect_type} 가 아닙니다: {header.get('type')}{where}")
    if expect_pk is not None and pk != expect_pk:
        raise MessageError(f"예상한 서명키로 서명되지 않았습니다{where}")
    return Msg(path, header, payload, raw, hb)


def read_msg(path: Path, expect_type: str | None = None, expect_pk: bytes | None = None) -> Msg:
    path = Path(path)
    if not path.exists():
        raise MessageError(f"메시지 파일이 없습니다: {path}")
    return parse_msg(path.read_bytes(), path, expect_type, expect_pk)


def sign_json(doc: dict, sk: SigningKey) -> dict:
    """JSON 문서(감사 응답 등)에 서명."""
    return _sign_body(doc, sk)


def verify_json(doc: dict, expect_pk: bytes | None = None) -> None:
    try:
        sig = bytes.fromhex(doc["sig"])
        pk = bytes.fromhex(doc["sig_pk"])
        body = {k: v for k, v in doc.items() if k != "sig"}
        VerifyKey(pk).verify(cjson(body), sig)
    except (KeyError, ValueError, BadSignatureError) as e:
        raise MessageError("문서 서명 검증 실패") from e
    if expect_pk is not None and pk != expect_pk:
        raise MessageError("예상한 서명키로 서명되지 않았습니다")
