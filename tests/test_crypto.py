import os

import pytest

from dualpsi import dleq, merkle
from dualpsi.group import (IDENTITY, Engine, GroupError, G, add, element_point, h2p, mul, mul_base, rand_scalar,
                           valid_point)


def test_group_basics():
    P = h2p(b"x")
    assert valid_point(P) and valid_point(G)
    assert not valid_point(IDENTITY)
    a, b = rand_scalar(), rand_scalar()
    assert mul(a, mul(b, P)) == mul(b, mul(a, P))  # 교환법칙 — PSI 의 핵심
    with pytest.raises(GroupError):
        mul(a, IDENTITY)
    torsion = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")  # 위수 8
    assert not valid_point(torsion)
    with pytest.raises(GroupError):
        mul(a, add(P, torsion))  # 소부분군 성분이 섞인 점 거부
    assert element_point(b"s1", "strict", "k") != element_point(b"s2", "strict", "k")  # 세션 분리


def test_dleq():
    k = rand_scalar()
    K = mul_base(k)
    P = h2p(b"p")
    Q = mul(k, P)
    pr = dleq.prove(k, G, K, P, Q, b"ctx")
    assert dleq.verify(pr, G, K, P, Q, b"ctx")
    assert not dleq.verify(pr, G, K, P, Q, b"other")
    assert not dleq.verify(pr, G, K, P, mul(rand_scalar(), P), b"ctx")
    assert not dleq.verify(pr[:32] + bytes(32), G, K, P, Q, b"ctx")
    assert not dleq.verify(b"\x00" * 10, G, K, P, Q, b"ctx")


@pytest.mark.parametrize("workers", [1, 2])
def test_batch_dleq(workers):
    k = rand_scalar()
    K = mul_base(k)
    with Engine(workers, chunk=37) as eng:
        U = eng.h2g_mul(os.urandom(32), rand_scalar(), "strict", [f"e{i}" for i in range(150)])
        D = eng.mul_all(k, U)
        pr = dleq.batch_prove(eng, k, K, U, D, b"c")
        assert dleq.batch_verify(eng, pr, K, U, D, b"c")
        for i in (0, 77, 149):
            bad = bytearray(D)
            bad[32 * i : 32 * i + 32] = mul(rand_scalar(), U[32 * i : 32 * i + 32])
            assert not dleq.batch_verify(eng, pr, K, U, bytes(bad), b"c")
        swapped = D[32:64] + D[:32] + D[64:]  # 순서 바꿔치기
        assert not dleq.batch_verify(eng, pr, K, U, swapped, b"c")
        assert not dleq.batch_verify(eng, pr, K, U, D[:-32], b"c")


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 33, 64, 100])
def test_merkle(n):
    leaves = [os.urandom(32) for _ in range(n)]
    t = merkle.Tree(leaves)
    assert t.root == merkle.root(leaves)
    for i in range(n):
        path = t.path(i)
        assert merkle.verify_path(t.root, n, i, leaves[i], path)
        assert not merkle.verify_path(t.root, n, i, os.urandom(32), path)
        assert not merkle.verify_path(t.root, n, n + i, leaves[i], path)  # 범위 밖 번호
        if n > 1:
            assert not merkle.verify_path(t.root, n, (i + 1) % n, leaves[i], path)
