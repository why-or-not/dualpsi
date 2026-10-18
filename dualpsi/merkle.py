"""솔트 머클 커밋. 명부 전체를 사전에 고정(바인딩)하되 내용은 숨긴다(솔트로 은닉).

- 잎: SHA-256(0x00 || DST || salt(32B) || record_bytes)
- 노드: SHA-256(0x01 || left || right), 홀수 개면 마지막 노드를 그대로 올린다.
- 트리 모양은 잎 개수 n 으로 완전히 결정되며 n 도 커밋에 포함된다.
"""

from __future__ import annotations

import hashlib

_LEAF = b"\x00dualpsi/v1/leaf"
_NODE = b"\x01"


def leaf_hash(salt: bytes, record_bytes: bytes) -> bytes:
    if len(salt) != 32:
        raise ValueError("salt 는 32바이트")
    return hashlib.sha256(_LEAF + salt + record_bytes).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(_NODE + l + r).digest()


def _next(level):
    nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])
    return nxt


def root(leaves) -> bytes:
    level = list(leaves)
    if not level:
        raise ValueError("빈 트리")
    while len(level) > 1:
        level = _next(level)
    return level[0]


class Tree:
    def __init__(self, leaves):
        if not leaves:
            raise ValueError("빈 트리")
        self.levels = [list(leaves)]
        while len(self.levels[-1]) > 1:
            self.levels.append(_next(self.levels[-1]))

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def path(self, index: int) -> list:
        out = []
        for level in self.levels[:-1]:
            sib = index ^ 1
            if sib < len(level):
                out.append(level[sib])
            index //= 2
        return out


def verify_path(root_: bytes, n: int, index: int, leaf: bytes, path: list) -> bool:
    if not (0 <= index < n):
        return False
    h, size, i = leaf, n, 0
    while size > 1:
        sib = index ^ 1
        if sib < size:
            if i >= len(path):
                return False
            s = path[i]
            i += 1
            h = _node(h, s) if index % 2 == 0 else _node(s, h)
        index //= 2
        size = (size + 1) // 2
    return i == len(path) and h == root_
