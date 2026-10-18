"""소수 위수 군 연산 (libsodium edwards25519 소수 위수 부분군, PyNaCl 공개 API).

- 모든 '받은' 점은 정규 인코딩·소위수 아님·주 부분군 소속을 검증한다(valid_point).
  libsodium의 scalarmult_ed25519_noclamp 도 입력 점에 같은 검증을 수행한다.
- 해시-투-군은 Elligator2 사상 두 번의 합(랜덤 오라클형 hash_to_curve 구성)이며
  libsodium from_uniform 이 cofactor를 제거하므로 결과는 주 부분군에 속한다.
- 대량 연산은 Engine 이 프로세스 풀로 병렬 처리한다.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ProcessPoolExecutor

from nacl import bindings as nb

from .util import lp

POINT = 32
IDENTITY = bytes([1]) + bytes(31)  # (0,1) 의 인코딩
_ONE = (1).to_bytes(32, "little")
G = nb.crypto_scalarmult_ed25519_base_noclamp(_ONE)

H2G_DST = b"dualpsi/v1/h2g"


class GroupError(ValueError):
    """잘못된 점 또는 스칼라."""


# ---------------------------------------------------------------- 스칼라

def h2s(*parts) -> bytes:
    """해시 → 스칼라 (mod L)."""
    return nb.crypto_core_ed25519_scalar_reduce(hashlib.sha512(lp(*parts)).digest())


def rand_scalar() -> bytes:
    while True:
        s = nb.crypto_core_ed25519_scalar_reduce(os.urandom(64))
        if s != bytes(32):
            return s


def sadd(a: bytes, b: bytes) -> bytes:
    return nb.crypto_core_ed25519_scalar_add(a, b)


def smul(a: bytes, b: bytes) -> bytes:
    return nb.crypto_core_ed25519_scalar_mul(a, b)


def canonical_scalar(s) -> bool:
    return isinstance(s, bytes) and len(s) == 32 and nb.crypto_core_ed25519_scalar_reduce(s + bytes(32)) == s


# ---------------------------------------------------------------- 점

def valid_point(P) -> bool:
    """정규 인코딩 + 소위수/항등원 아님 + 주 부분군 소속."""
    return isinstance(P, bytes) and len(P) == 32 and bool(nb.crypto_core_ed25519_is_valid_point(P))


def mul(s: bytes, P: bytes) -> bytes:
    try:
        return nb.crypto_scalarmult_ed25519_noclamp(s, P)
    except Exception as e:  # libsodium 이 입력 점 검증에 실패하거나 결과가 항등원
        raise GroupError("잘못된 점 또는 스칼라") from e


def mul_base(s: bytes) -> bytes:
    try:
        return nb.crypto_scalarmult_ed25519_base_noclamp(s)
    except Exception as e:
        raise GroupError("잘못된 스칼라") from e


def add(P: bytes, Q: bytes) -> bytes:
    try:
        return nb.crypto_core_ed25519_add(P, Q)
    except Exception as e:
        raise GroupError("잘못된 점") from e


def sub(P: bytes, Q: bytes) -> bytes:
    try:
        return nb.crypto_core_ed25519_sub(P, Q)
    except Exception as e:
        raise GroupError("잘못된 점") from e


def h2p(*parts) -> bytes:
    """해시 → 군 원소 (랜덤 오라클형: 두 Elligator2 사상의 합)."""
    h = hashlib.sha512(lp(*parts)).digest()
    return nb.crypto_core_ed25519_add(
        nb.crypto_core_ed25519_from_uniform(h[:32]),
        nb.crypto_core_ed25519_from_uniform(h[32:]),
    )


def element_point(sid: bytes, tier: str, key: str) -> bytes:
    """세션별 원소 해시 H_sid(tier, key). 세션이 다르면 값도 달라 재사용·사전계산이 불가하다."""
    return h2p(H2G_DST, sid, tier, key)


def split_points(blob: bytes) -> list:
    return [blob[i : i + POINT] for i in range(0, len(blob), POINT)]


def acc_add(acc, P):
    """항등원(None)을 허용하는 누적 덧셈."""
    if P is None:
        return acc
    if acc is None:
        return P
    r = add(acc, P)
    return None if r == IDENTITY else r


# ---------------------------------------------------------------- 병렬 작업 (최상위 함수여야 pickle 가능)

def _job_h2g_mul(sid, scalar, tier, keys):
    out = bytearray()
    for k in keys:
        out += nb.crypto_scalarmult_ed25519_noclamp(scalar, element_point(sid, tier, k))
    return bytes(out)


def _job_mul(scalar, blob, base_index):
    out = bytearray()
    for off in range(0, len(blob), POINT):
        try:
            out += nb.crypto_scalarmult_ed25519_noclamp(scalar, blob[off : off + POINT])
        except Exception:
            raise GroupError(f"잘못된 점 (위치 {base_index + off // POINT})") from None
    return bytes(out)


def _job_lincomb(seed, start, blob_p, blob_q):
    acc_p = acc_q = None
    for idx, off in enumerate(range(0, len(blob_p), POINT)):
        c = h2s(seed, start + idx)
        acc_p = acc_add(acc_p, mul(c, blob_p[off : off + POINT]))
        if blob_q is not None:
            acc_q = acc_add(acc_q, mul(c, blob_q[off : off + POINT]))
    return acc_p, acc_q


class Engine:
    """대량 군 연산을 청크 단위로 병렬 처리한다. `with Engine(workers) as eng:` 로 사용."""

    def __init__(self, workers=None, chunk=4096):
        self.workers = max(1, workers if workers else (os.cpu_count() or 1))
        self.chunk = chunk
        self._pool = None

    def __enter__(self):
        if self.workers > 1:
            self._pool = ProcessPoolExecutor(self.workers)
        return self

    def __exit__(self, *exc):
        if self._pool is not None:
            self._pool.shutdown(cancel_futures=True)
            self._pool = None

    def _run(self, fn, jobs):
        if self._pool is None or len(jobs) <= 1:
            return [fn(*j) for j in jobs]
        futs = [self._pool.submit(fn, *j) for j in jobs]
        return [f.result() for f in futs]

    def _blob_jobs(self, blob):
        step = self.chunk * POINT
        return [(i, blob[i : i + step]) for i in range(0, len(blob), step)]

    def h2g_mul(self, sid, scalar, tier, keys) -> bytes:
        """[k·H_sid(tier, key) for key in keys] 를 이어 붙인 바이트."""
        jobs = [(sid, scalar, tier, keys[i : i + self.chunk]) for i in range(0, len(keys), self.chunk)]
        return b"".join(self._run(_job_h2g_mul, jobs))

    def mul_all(self, scalar, blob) -> bytes:
        """각 점에 스칼라 곱. 입력 점이 잘못되면 GroupError."""
        jobs = [(scalar, part, off // POINT) for off, part in self._blob_jobs(blob)]
        return b"".join(self._run(_job_mul, jobs))

    def lincomb(self, seed, blob_p, blob_q=None):
        """(Σ c_i·P_i, Σ c_i·Q_i), c_i = h2s(seed, i). 계수는 Fiat–Shamir 로 유도."""
        step = self.chunk * POINT
        jobs = []
        for off in range(0, len(blob_p), step):
            jobs.append((seed, off // POINT, blob_p[off : off + step],
                         None if blob_q is None else blob_q[off : off + step]))
        acc_p = acc_q = None
        for p, q in self._run(_job_lincomb, jobs):
            acc_p = acc_add(acc_p, p)
            acc_q = acc_add(acc_q, q)
        return acc_p, acc_q
