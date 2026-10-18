"""Chaum–Pedersen DLEQ 영지식 증명 (Fiat–Shamir 비대화형).

명제: log_{B1} A1 = log_{B2} A2  (= 비밀 키 k)
  - 단일 증명: 감사에서 "공개한 레코드의 해시에 커밋한 키를 적용한 값이 1라운드 값과 같다"
  - 배치 증명: 2라운드에서 "상대 원소 전부에 같은 키 k 를 빠짐없이·바꿔치기 없이 적용했다"
키 k 자체는 드러나지 않는다.
"""

from __future__ import annotations

import hashlib
import hmac

from .group import G, GroupError, canonical_scalar, h2s, mul, rand_scalar, sadd, smul, sub
from .util import H, lp

DLEQ_DST = b"dualpsi/v1/dleq"


def prove(k: bytes, B1: bytes, A1: bytes, B2: bytes, A2: bytes, ctx: bytes) -> bytes:
    r = rand_scalar()
    T1 = mul(r, B1)
    T2 = mul(r, B2)
    c = h2s(DLEQ_DST, ctx, B1, A1, B2, A2, T1, T2)
    s = sadd(r, smul(c, k))
    return c + s


def verify(proof: bytes, B1: bytes, A1: bytes, B2: bytes, A2: bytes, ctx: bytes) -> bool:
    if not isinstance(proof, bytes) or len(proof) != 64:
        return False
    c, s = proof[:32], proof[32:]
    if not (canonical_scalar(c) and canonical_scalar(s)):
        return False
    try:
        T1 = sub(mul(s, B1), mul(c, A1))
        T2 = sub(mul(s, B2), mul(c, A2))
    except GroupError:
        return False
    return hmac.compare_digest(c, h2s(DLEQ_DST, ctx, B1, A1, B2, A2, T1, T2))


# ------------------------------------------------------------- 배치: Q_i = k·P_i (모든 i)

def _batch_seed(ctx, K, blob_p, blob_q) -> bytes:
    return H(b"dualpsi/v1/batch", ctx, K, len(blob_p) // 32,
             hashlib.sha256(blob_p).digest(), hashlib.sha256(blob_q).digest())


def batch_prove(engine, k: bytes, K: bytes, blob_p: bytes, blob_q: bytes, ctx: bytes) -> bytes:
    if not blob_p:
        return b""
    seed = _batch_seed(ctx, K, blob_p, blob_q)
    P_star, _ = engine.lincomb(seed, blob_p)
    if P_star is None:
        raise GroupError("배치 결합이 항등원 — 입력이 비정상입니다")
    return prove(k, G, K, P_star, mul(k, P_star), lp(ctx, seed))


def batch_verify(engine, proof: bytes, K: bytes, blob_p: bytes, blob_q: bytes, ctx: bytes) -> bool:
    """모든 i 에 대해 Q_i = k·P_i 인지 확인. 하나라도 다르면 ≈1/L 확률로만 통과."""
    if len(blob_p) != len(blob_q) or len(blob_p) % 32:
        return False
    if not blob_p:
        return proof == b""
    seed = _batch_seed(ctx, K, blob_p, blob_q)
    try:
        P_star, Q_star = engine.lincomb(seed, blob_p, blob_q)
    except GroupError:
        return False
    if P_star is None or Q_star is None:
        return False
    return verify(proof, G, K, P_star, Q_star, lp(ctx, seed))
