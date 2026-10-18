"""두 당(X, Y)과 중립 중개인(H) 사이의 이중당적자 산출 프로토콜.

  hub-init 중개인(선관위·공증인 등 양측이 합의한 기관)이 서명키와 봉인용 공개키를 공개
  setup    각 당이 명부를 정규화하고 솔트 머클 루트(R)와 레코드 수(n)를 서명 공개 → 사전 커밋
  round1   sid = H(두 setup, 중개인, 세션 파라미터). 각자 비밀키 k, 공개키 K = k·G
           원소 e(등급별 매칭 키)마다 U = k·H_sid(e) 를 PRF 순서로 상대에게 보낸다(+감사 난수 커밋)
  round2   상대의 U 전부에 내 키를 적용한 D = k·U 와 "모든 원소에 같은 k 를 빠짐없이 적용했다"는
           배치 DLEQ 영지식 증명을 중개인의 공개키로 봉인해 중개인에게만 보낸다
  mediate  중개인이 양쪽 증명을 검증하고 (k_X·k_Y)·H(e) 가 같은 쌍을 찾아, 서명한 결과를 양측에 동시에 배포
           명단 모드: 매칭 위치 쌍과 그 값 / 건수 모드: 건수만
  finalize 각 당이 결과를 받아 매칭 값을 자기 키로 다시 계산해 확인하고, 수락 또는 거부를 서명해 남긴다
  confirm  상대도 '같은 결과'를 수락했는지 확인한 뒤에만 결과를 확정한다. 중개인이 가짜 쌍을 넣으면 적어도
           한쪽의 재확인이 실패하고, 그 거부가 이 단계에서 다른 쪽에도 전달되어 어느 쪽도 확정하지 않는다
           (건수 모드의 건수 자체는 양당이 다시 셀 수 없으므로 중개인을 믿어야 한다)
  audit    양측 커밋 난수로 정한 무작위 위치와 매칭 위치를 감사인에게만 공개:
           레코드 + 솔트 + 머클 경로 + "U = k·H(레코드 키)" DLEQ 증명 → 감사인이 실당원 여부를 증빙과 대조

왜 중개인인가
  두 당이 2라운드 값을 직접 주고받으면, 한쪽이 자기 키를 쓰지 않은 '떠보기' 원소(H(추측) 등)를
  1라운드에 섞어 보낸 뒤, 돌려받은 k_상대·H(추측) 을 상대의 1라운드 값과 비교해 상대 명부를 몰래
  조회할 수 있다. 이 조회는 교집합에 나타나지 않아 매칭 감사로도 잡히지 않는다.
  2라운드 값을 중개인만 보게 하면 떠보기로 얻을 정보가 없어지고, 끼워넣기는 반드시 양측에 보이는
  매칭으로만 나타나 감사에서 드러난다.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey

from . import PROTOCOL, dleq, merkle
from .group import G, Engine, GroupError, element_point, mul_base, rand_scalar, split_points, valid_point
from .messages import Msg, read_msg, sign_json, write_msg
from .normalize import NORM_VERSION, TIERS, default_pivot, load_roster
from .util import H, cjson, fingerprint, fp_normalize, lp, now_iso, prf, unlp, write_private_bytes, write_private_json

LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MODES = ("list", "count")
R2_DST = b"dualpsi/v1/round2-inner"
PAIR = struct.Struct(">III32s")  # 세그먼트, 첫째 위치, 둘째 위치, 매칭 값


class ProtocolError(Exception):
    """절차·형식 오류."""


class VerificationError(ProtocolError):
    """검증 실패 — 조작·손상 가능성."""


# ======================================================================= 파라미터·식별자

def make_params(mode="list", tiers=("strict",), audit_k=200, purpose="") -> dict:
    if mode not in MODES:
        raise ProtocolError(f"mode 는 {MODES} 중 하나: {mode}")
    tiers = list(tiers)
    if not tiers or any(t not in TIERS for t in tiers) or len(set(tiers)) != len(tiers):
        raise ProtocolError(f"tiers 는 {TIERS} 의 부분집합: {tiers}")
    if int(audit_k) < 0:
        raise ProtocolError("audit_k 는 0 이상")
    return {"mode": mode, "tiers": [t for t in TIERS if t in tiers], "audit_k": int(audit_k), "purpose": str(purpose)}


def compute_sid(setup_a: Msg, setup_b: Msg, hub: Msg, params: dict, session: str) -> bytes:
    a, b = sorted([setup_a.msg_id, setup_b.msg_id])
    return H(b"dualpsi/v1/sid", PROTOCOL, a, b, hub.msg_id, cjson(params), session)


def ctx_round2(sid: bytes, target_r1_id: bytes) -> bytes:
    return lp(b"dualpsi/v1/round2", sid, target_r1_id)


def ctx_audit(sid: bytes, r1_id: bytes, seg: int, pos: int) -> bytes:
    return lp(b"dualpsi/v1/audit", sid, r1_id, seg, pos)


def nonce_commit(nonce: bytes) -> str:
    return H(b"dualpsi/v1/nonce", nonce).hex()


def seg_ranges(segments) -> list:
    out, s = [], 0
    for sg in segments:
        out.append((s, s + sg["count"]))
        s += sg["count"]
    return out


def point_at(r1: Msg, seg: int, pos: int) -> bytes:
    off = seg_ranges(r1.header["segments"])[seg][0] + pos
    return r1.payload[32 * off : 32 * off + 32]


# ======================================================================= 명부 → 잎·원소

@dataclass
class LeafRoster:
    records: list
    lines: list
    salts: list
    leaves: list
    _elements: dict = field(default_factory=dict)

    @classmethod
    def build(cls, seed: bytes, recmap: dict) -> "LeafRoster":
        k_order = prf(seed, "leaf-order")
        k_salt = prf(seed, "leaf-salt")
        items = sorted(recmap.items(), key=lambda kv: prf(k_order, kv[0].to_bytes()))
        records = [r for r, _ in items]
        lines = [l for _, l in items]
        salts = [prf(k_salt, i) for i in range(len(records))]
        leaves = [merkle.leaf_hash(s, r.to_bytes()) for s, r in zip(salts, records)]
        return cls(records, lines, salts, leaves)

    def root(self) -> bytes:
        return merkle.root(self.leaves)

    def elements(self, tier: str) -> dict:
        """매칭 키 → 그 키를 만드는 잎 번호들."""
        if tier not in self._elements:
            m: dict = {}
            for i, r in enumerate(self.records):
                k = r.key(tier)
                if k is not None:
                    m.setdefault(k, []).append(i)
            self._elements[tier] = m
        return self._elements[tier]


@dataclass
class Segment:
    tier: str
    keys: list


def layout(seed: bytes, sid: bytes, roster: LeafRoster, params: dict) -> list:
    """세션별 원소 배치. 비밀 키 기반 PRF 정렬이라 위치가 가입 순서 등과 무관하다."""
    k_item = prf(seed, "item-order", sid)
    return [Segment(t, sorted(roster.elements(t).keys(), key=lambda k: prf(k_item, t, k))) for t in params["tiers"]]


# ======================================================================= 공통 검증 (당사자·중개인·감사인 공용)

def check_round1_pair(r1_x: Msg, r1_y: Msg, setup_x: Msg, setup_y: Msg, hub: Msg):
    """두 1라운드가 같은 setup·중개인·세션·파라미터에 속하고 형식이 맞는지 확인. (sid, params) 반환."""
    for r1, st, other in ((r1_x, setup_x, setup_y), (r1_y, setup_y, setup_x)):
        h = r1.header
        who = st.header["label"]
        if h.get("protocol") != PROTOCOL or h.get("label") != who:
            raise VerificationError(f"{who}의 1라운드 형식 오류")
        if (h.get("setup_id") != st.msg_id.hex() or h.get("peer_setup_id") != other.msg_id.hex()
                or h.get("hub_id") != hub.msg_id.hex()):
            raise VerificationError(f"{who}의 1라운드가 교환된 setup·중개인과 연결되지 않습니다")
        params = h.get("params")
        try:
            if make_params(**params) != params:
                raise ProtocolError("정규화되지 않은 파라미터")
        except (TypeError, ProtocolError) as e:
            raise VerificationError(f"{who}의 세션 파라미터 오류: {e}") from None
        if h.get("sid") != compute_sid(st, other, hub, params, h.get("session", "")).hex():
            raise VerificationError(f"{who}의 세션 ID 가 setup·중개인·파라미터와 맞지 않습니다")
        try:
            if not valid_point(bytes.fromhex(h["psi_pk"])):
                raise ValueError
        except (KeyError, ValueError):
            raise VerificationError(f"{who}의 PSI 공개키가 올바르지 않습니다") from None
        segs = h.get("segments") or []
        if [sg.get("tier") for sg in segs] != params["tiers"]:
            raise VerificationError(f"{who}의 세그먼트 구성이 파라미터와 다릅니다")
        for sg in segs:
            c = sg.get("count")
            if not isinstance(c, int) or c < 0 or set(sg) != {"tier", "count"}:
                raise VerificationError(f"{who}의 세그먼트 형식 오류")
            if c > st.header["n_leaves"]:
                raise VerificationError(f"{who}의 원소 수({c})가 커밋한 명부 크기({st.header['n_leaves']})를 넘습니다")
        if len(r1.payload) != 32 * sum(sg["count"] for sg in segs):
            raise VerificationError(f"{who}의 1라운드 페이로드 크기 오류")
    hx, hy = r1_x.header, r1_y.header
    if hx["sid"] != hy["sid"] or hx["session"] != hy["session"] or cjson(hx["params"]) != cjson(hy["params"]):
        raise VerificationError(
            "두 당사자의 세션/파라미터가 다릅니다 — 양측이 같은 --mode/--tiers/--audit-k/--purpose 로 round1 을 실행해야 합니다\n"
            f"  {hx['label']}: {hx['params']}\n  {hy['label']}: {hy['params']}")
    return bytes.fromhex(hx["sid"]), hx["params"]


def check_distinct(blob: bytes, segments, what: str) -> None:
    for a, b in seg_ranges(segments):
        if len(set(split_points(blob[32 * a : 32 * b]))) != b - a:
            raise VerificationError(f"{what}에 중복 원소가 있습니다")


def audit_seed_of(sid: bytes, r1_first: Msg, nonce_first: bytes, r1_second: Msg, nonce_second: bytes) -> bytes:
    """양측이 1라운드에 커밋하고 2라운드에 공개한 난수로 감사 위치를 정한다(어느 쪽도 혼자 고를 수 없다)."""
    return H(b"dualpsi/v1/audit-seed", sid, r1_first.msg_id, nonce_first, r1_second.msg_id, nonce_second)


def challenge_positions(seed: bytes, r1: Msg, k: int) -> list:
    counts = [sg["count"] for sg in r1.header["segments"]]
    total = sum(counts)
    k = min(k, total)
    chosen, ctr = set(), 0
    while len(chosen) < k:
        chosen.add(int.from_bytes(prf(seed, "challenge", r1.msg_id, ctr), "big") % total)
        ctr += 1
    out = []
    for g in sorted(chosen):
        s = 0
        while g >= counts[s]:
            g -= counts[s]
            s += 1
        out.append((s, g))
    return out


def encode_pairs(pairs: list) -> bytes:
    return b"".join(PAIR.pack(s, i, j, v) for s, i, j, v in sorted(pairs))


def decode_pairs(payload: bytes) -> list:
    if len(payload) % PAIR.size:
        raise VerificationError("매칭 결과 형식 오류")
    return [PAIR.unpack_from(payload, off) for off in range(0, len(payload), PAIR.size)]


def match_pairs(r1_x: Msg, D_x: bytes, r1_y: Msg, D_y: bytes) -> list:
    """D_x: x 원소의 이중암호화(x 순서), D_y: y 원소(y 순서) → [(세그먼트, x위치, y위치, 값)]."""
    pairs = []
    for s, ((ax, bx), (ay, by)) in enumerate(zip(seg_ranges(r1_x.header["segments"]),
                                                  seg_ranges(r1_y.header["segments"]))):
        idx = {D_y[32 * j : 32 * j + 32]: j - ay for j in range(ay, by)}
        for i in range(ax, bx):
            v = D_x[32 * i : 32 * i + 32]
            j = idx.get(v)
            if j is not None:
                pairs.append((s, i - ax, j, v))
    return pairs


def check_result(res: Msg, hub: Msg, setups: dict, r1: dict) -> dict:
    """중개인 결과 메시지가 이 세션·1라운드에 대한 것인지, 감사 난수가 커밋과 맞는지 검증.
    setups/r1: {라벨: Msg}. 반환: {order, sid, params, nonces, audit_seed, counts, pairs}."""
    h = res.header
    order = sorted(setups, key=lambda l: setups[l].msg_id)
    a, b = order
    if h.get("protocol") != PROTOCOL or h.get("label") != hub.header["label"] or h.get("type") != "result":
        raise VerificationError("중개인 결과 형식 오류")
    if h.get("sid") != r1[a].header["sid"] or h.get("session") != r1[a].header["session"]:
        raise VerificationError("중개인 결과가 이 세션에 대한 것이 아닙니다")
    if h.get("parties") != order or h.get("round1_ids") != [r1[a].msg_id.hex(), r1[b].msg_id.hex()]:
        raise VerificationError("중개인 결과가 이 1라운드 메시지들에 대한 것이 아닙니다")
    params = r1[a].header["params"]
    if h.get("mode") != params["mode"] or h.get("tiers") != params["tiers"]:
        raise VerificationError("중개인 결과의 모드·등급이 세션과 다릅니다")
    try:
        nonces = [bytes.fromhex(x) for x in h["nonces"]]
    except (KeyError, ValueError, TypeError):
        raise VerificationError("중개인 결과의 감사 난수 형식 오류") from None
    for l, n in zip(order, nonces):
        if nonce_commit(n) != r1[l].header["nonce_commit"]:
            raise VerificationError(f"{l}의 감사 난수가 1라운드 커밋과 다릅니다")
    sid = bytes.fromhex(h["sid"])
    seed = audit_seed_of(sid, r1[a], nonces[0], r1[b], nonces[1])
    if h.get("audit_seed") != seed.hex():
        raise VerificationError("감사 난수 계산이 맞지 않습니다")
    counts = h.get("counts")
    if not isinstance(counts, list) or [c.get("tier") for c in counts] != params["tiers"]:
        raise VerificationError("중개인 결과의 건수 형식 오류")
    pairs = None
    if params["mode"] == "list":
        if h.get("pairs_sha256") != hashlib.sha256(res.payload).hexdigest():
            raise VerificationError("매칭 결과 해시 불일치")
        pairs = decode_pairs(res.payload)
        segs_a, segs_b = r1[a].header["segments"], r1[b].header["segments"]
        seen_a, seen_b = set(), set()
        for s, i, j, _ in pairs:
            if not (s < len(segs_a) and i < segs_a[s]["count"] and j < segs_b[s]["count"]):
                raise VerificationError("매칭 결과에 범위를 벗어난 위치가 있습니다")
            if (s, i) in seen_a or (s, j) in seen_b:
                raise VerificationError("매칭 결과에 중복 위치가 있습니다")
            seen_a.add((s, i))
            seen_b.add((s, j))
        if [c.get("matches") for c in counts] != [sum(1 for p in pairs if p[0] == s) for s in range(len(params["tiers"]))]:
            raise VerificationError("매칭 쌍 수와 건수가 다릅니다")
    else:
        if res.payload:
            raise VerificationError("건수 모드 결과에 매칭 정보가 들어 있습니다")
        for c, sa, sb in zip(counts, r1[a].header["segments"], r1[b].header["segments"]):
            m = c.get("matches")
            if not isinstance(m, int) or isinstance(m, bool) or not 0 <= m <= min(sa["count"], sb["count"]):
                raise VerificationError("중개인 결과의 건수가 가능한 범위를 벗어납니다")
    return {"order": order, "sid": sid, "params": params, "nonces": nonces, "audit_seed": seed,
            "counts": counts, "pairs": pairs}


# ======================================================================= 공통 기반

class _Actor:
    role = ""

    def __init__(self, work, exchange, workers: int | None = None):
        self.work, self.exchange = Path(work), Path(exchange)
        sp = self.work / "secret.json"
        if not sp.exists():
            raise ProtocolError(f"{sp} 가 없습니다. 먼저 {'hub-init' if self.role == 'hub' else 'setup'} 을 실행하세요")
        self.secret = json.loads(sp.read_text("utf-8"))
        if self.secret.get("role") != self.role:
            raise ProtocolError(f"{self.work} 는 {self.role} 작업 폴더가 아닙니다")
        self.label = self.secret["label"]
        self.sk = SigningKey(bytes.fromhex(self.secret["sign_sk"]))
        self.pk = self.sk.verify_key.encode()
        self.workers = workers

    def save(self) -> None:
        write_private_json(self.work / "secret.json", self.secret)

    def reload(self) -> None:
        self.secret = json.loads((self.work / "secret.json").read_text("utf-8"))

    def xpath(self, label: str, kind: str, session: str | None = None) -> Path:
        if kind in ("setup", "hub"):
            return self.exchange / f"{label}.{kind}.msg"
        return self.exchange / f"{label}.{session}.{kind}.msg"

    def _one(self, suffix: str, exclude: str | None = None) -> Msg:
        cands = sorted(p for p in self.exchange.glob(f"*.{suffix}.msg") if p.name != exclude)
        if len(cands) != 1:
            raise ProtocolError(f"교환 폴더 {self.exchange} 에 *.{suffix}.msg 가 정확히 하나 있어야 합니다 (현재 {len(cands)}개)")
        m = read_msg(cands[0], suffix)
        if f"{m.header['label']}.{suffix}.msg" != cands[0].name:
            raise ProtocolError(f"{cands[0].name}: 파일 이름과 내부 라벨이 다릅니다")
        return m

    def sessions(self) -> dict:
        return self.secret.setdefault("sessions", {})

    def session(self, name: str, require: bool = True) -> dict | None:
        s = self.sessions().get(name)
        if require and s is None:
            raise ProtocolError(f"세션 '{name}' 이(가) 없습니다")
        return s


# ======================================================================= 중개인

def hub_init(work, exchange, label: str, display_name: str = "") -> dict:
    if not LABEL_RE.match(label or ""):
        raise ProtocolError("라벨은 영문·숫자·_·- 1~32자여야 합니다 (예: HUB)")
    work, exchange = Path(work), Path(exchange)
    if (work / "secret.json").exists():
        raise ProtocolError(f"{work} 는 이미 초기화된 작업 폴더입니다")
    sk, ek = SigningKey.generate(), PrivateKey.generate()
    created = now_iso()
    write_private_json(work / "secret.json", {
        "version": 1, "protocol": PROTOCOL, "role": "hub", "label": label, "display_name": display_name,
        "sign_sk": sk.encode().hex(), "enc_sk": ek.encode().hex(), "created_at": created, "sessions": {}})
    m = write_msg(exchange / f"{label}.hub.msg",
                  {"type": "hub", "protocol": PROTOCOL, "label": label, "display_name": display_name,
                   "enc_pk": ek.public_key.encode().hex(), "nonce": os.urandom(16).hex(), "created_at": created},
                  b"", sk)
    return {"label": label, "fingerprint": fingerprint(sk.verify_key.encode()), "path": str(m.path)}


def open_round2(r2: Msg, enc_sk: PrivateKey) -> tuple:
    """봉인된 2라운드를 연다 → (sid, 대상 1라운드 ID, 난수, 증명, D)."""
    try:
        parts = unlp(SealedBox(enc_sk).decrypt(r2.payload))
    except (CryptoError, ValueError):
        raise VerificationError(f"{r2.header.get('label')}의 2라운드를 열 수 없습니다(다른 중개인용이거나 손상)") from None
    if len(parts) != 6 or parts[0] != R2_DST:
        raise VerificationError("2라운드 내부 형식 오류")
    return tuple(parts[1:])


def verify_round2(eng: Engine, sid: bytes, r1_target: Msg, r1_prover: Msg, r2_prover: Msg,
                  enc_sk: PrivateKey) -> tuple:
    """r2_prover 가 r1_target 의 원소 전부에 자기 키를 올바르게 적용했는지 검증 → (D, 난수)."""
    h = r2_prover.header
    who = r1_prover.header["label"]
    if (h.get("protocol") != PROTOCOL or h.get("sid") != sid.hex() or h.get("session") != r1_target.header["session"]
            or h.get("label") != who or h.get("hub_id") != r1_target.header["hub_id"]):
        raise VerificationError(f"{who}의 2라운드가 이 세션에 속하지 않습니다")
    if h.get("peer_round1_id") != r1_target.msg_id.hex() or h.get("segments") != r1_target.header["segments"]:
        raise VerificationError(f"{who}의 2라운드가 상대 1라운드에 대한 응답이 아닙니다")
    if h.get("sealed_to") != enc_sk.public_key.encode().hex():
        raise VerificationError(f"{who}의 2라운드가 이 중개인에게 봉인되지 않았습니다")
    in_sid, in_r1, nonce, proof, D = open_round2(r2_prover, enc_sk)
    if in_sid != sid or in_r1 != r1_target.msg_id:
        raise VerificationError(f"{who}의 2라운드 내부 내용이 헤더와 다릅니다")
    if nonce_commit(nonce) != r1_prover.header["nonce_commit"]:
        raise VerificationError(f"{who}의 감사 난수 공개값이 1라운드 커밋과 다릅니다")
    U = r1_target.payload
    if len(D) != len(U):
        raise VerificationError(f"{who}의 2라운드 원소 수가 상대 1라운드와 다릅니다")
    K = bytes.fromhex(r1_prover.header["psi_pk"])
    if not dleq.batch_verify(eng, proof, K, U, D, ctx_round2(sid, r1_target.msg_id)):
        raise VerificationError(f"{who}의 이중암호화 증명(DLEQ) 검증 실패 — 값이 조작되었거나 손상되었습니다")
    return D, nonce


class Hub(_Actor):
    role = "hub"

    def __init__(self, work, exchange, workers: int | None = None):
        super().__init__(work, exchange, workers)
        self.enc_sk = PrivateKey(bytes.fromhex(self.secret["enc_sk"]))

    def own_hub(self) -> Msg:
        return read_msg(self.xpath(self.label, "hub"), "hub", self.pk)

    def setups(self) -> dict:
        out = {}
        for p in sorted(self.exchange.glob("*.setup.msg")):
            m = read_msg(p, "setup")
            if f"{m.header['label']}.setup.msg" != p.name:
                raise ProtocolError(f"{p.name}: 파일 이름과 내부 라벨이 다릅니다")
            out[m.header["label"]] = m
        if len(out) != 2:
            raise ProtocolError(f"교환 폴더에 두 당의 setup 메시지가 있어야 합니다 (현재 {len(out)}개)")
        if self.label in out:
            raise ProtocolError("중개인 라벨이 당사자 라벨과 같습니다")
        return out

    def compute(self, session: str) -> dict:
        """양측 2라운드를 열고 검증해 결과를 계산한다(파일은 쓰지 않음)."""
        hub = self.own_hub()
        setups = self.setups()
        a, b = sorted(setups, key=lambda l: setups[l].msg_id)
        r1 = {l: read_msg(self.xpath(l, "round1", session), "round1", setups[l].pk) for l in (a, b)}
        r2 = {l: read_msg(self.xpath(l, "round2", session), "round2", setups[l].pk) for l in (a, b)}
        sid, params = check_round1_pair(r1[a], r1[b], setups[a], setups[b], hub)
        with Engine(self.workers) as eng:
            D_a, nonce_b = verify_round2(eng, sid, r1[a], r1[b], r2[b], self.enc_sk)  # b 가 a 원소를 처리
            D_b, nonce_a = verify_round2(eng, sid, r1[b], r1[a], r2[a], self.enc_sk)
        pairs = match_pairs(r1[a], D_a, r1[b], D_b)
        counts = [sum(1 for p in pairs if p[0] == s) for s in range(len(params["tiers"]))]
        return {"order": [a, b], "sid": sid, "params": params, "r1": r1, "r2": r2,
                "nonces": [nonce_a, nonce_b], "pairs": pairs, "counts": counts,
                "audit_seed": audit_seed_of(sid, r1[a], nonce_a, r1[b], nonce_b)}

    def mediate(self, session: str) -> dict:
        self.reload()
        out = self.xpath(self.label, "result", session)
        if out.exists():
            raise ProtocolError(f"이미 결과를 배포한 세션입니다: {out.name}")
        c = self.compute(session)
        a, b = c["order"]
        params = c["params"]
        payload = encode_pairs(c["pairs"]) if params["mode"] == "list" else b""
        header = {"type": "result", "protocol": PROTOCOL, "label": self.label, "session": session,
                  "sid": c["sid"].hex(), "mode": params["mode"], "tiers": params["tiers"], "parties": [a, b],
                  "round1_ids": [c["r1"][a].msg_id.hex(), c["r1"][b].msg_id.hex()],
                  "round2_ids": [c["r2"][a].msg_id.hex(), c["r2"][b].msg_id.hex()],
                  "nonces": [n.hex() for n in c["nonces"]], "audit_seed": c["audit_seed"].hex(),
                  "counts": [{"tier": t, "matches": n} for t, n in zip(params["tiers"], c["counts"])],
                  "pairs_sha256": hashlib.sha256(payload).hexdigest() if params["mode"] == "list" else None,
                  "created_at": now_iso()}
        write_msg(out, header, payload, self.sk)
        self.sessions()[session] = {"sid": c["sid"].hex(), "mode": params["mode"], "parties": [a, b],
                                    "counts": header["counts"], "mediated_at": header["created_at"]}
        self.save()
        return {"parties": [a, b], "mode": params["mode"], "counts": header["counts"], "send": out.name}


# ======================================================================= 당사자

def setup(work, exchange, label: str, roster, display_name: str = "", columns: dict | None = None,
          pivot_yy: int | None = None, max_records: int | None = None) -> dict:
    if not LABEL_RE.match(label or ""):
        raise ProtocolError("라벨은 영문·숫자·_·- 1~32자여야 합니다 (예: DP, RKP)")
    work, exchange = Path(work), Path(exchange)
    if (work / "secret.json").exists():
        raise ProtocolError(f"{work} 는 이미 setup 된 작업 폴더입니다")
    pivot = default_pivot() if pivot_yy is None else int(pivot_yy)
    rd = load_roster(roster, pivot, columns)
    if not rd.records:
        raise ProtocolError("유효한 명부 레코드가 하나도 없습니다")
    seed = os.urandom(32)
    sk = SigningKey.generate()
    lr = LeafRoster.build(seed, rd.records)
    n = len(lr.records)
    if max_records and n > max_records:
        raise ProtocolError(f"레코드 수 {n} 가 상한 {max_records} 를 넘습니다")
    root = lr.root()
    work.mkdir(parents=True, exist_ok=True)
    exchange.mkdir(parents=True, exist_ok=True)
    secret = {
        "version": 1, "protocol": PROTOCOL, "role": "party", "label": label, "display_name": display_name,
        "sign_sk": sk.encode().hex(), "seed": seed.hex(),
        "roster": {"path": str(Path(roster).resolve()), "sha256": rd.sha256,
                   "columns": rd.columns, "encoding": rd.encoding},
        "norm": {"version": NORM_VERSION, "pivot_yy": pivot},
        "n_leaves": n, "root": root.hex(), "created_at": now_iso(), "sessions": {},
    }
    write_private_json(work / "secret.json", secret)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["명부_줄번호", "사유"])
    w.writerows(rd.rejects)
    write_private_bytes(work / "rejects.csv", buf.getvalue().encode("utf-8-sig"))
    header = {"type": "setup", "protocol": PROTOCOL, "label": label, "display_name": display_name,
              "norm": secret["norm"], "root": root.hex(), "n_leaves": n,
              "nonce": os.urandom(16).hex(), "created_at": secret["created_at"]}
    m = write_msg(exchange / f"{label}.setup.msg", header, b"", sk)
    valid_rows = rd.total_rows - len(rd.rejects)
    return {"label": label, "fingerprint": fingerprint(sk.verify_key.encode()), "n_leaves": n,
            "total_rows": rd.total_rows, "rejects": len(rd.rejects), "duplicates": valid_rows - n,
            "phone_missing": rd.phone_missing, "encoding": rd.encoding, "columns": rd.columns,
            "setup_path": str(m.path), "root": root.hex()}


class Party(_Actor):
    role = "party"

    def __init__(self, work, exchange, workers: int | None = None, roster_path=None):
        super().__init__(work, exchange, workers)
        self.seed = bytes.fromhex(self.secret["seed"])
        self._roster_path = roster_path
        self._roster = None

    def sdir(self, session: str) -> Path:
        d = self.work / "sessions" / session
        d.mkdir(parents=True, exist_ok=True)
        return d

    def own_setup(self) -> Msg:
        return read_msg(self.xpath(self.label, "setup"), "setup", self.pk)

    def peer_setup(self) -> Msg:
        m = self._one("setup", exclude=f"{self.label}.setup.msg")
        if m.pk == self.pk or m.header["label"] == self.label:
            raise ProtocolError("상대 setup 이 우리 것과 같습니다")
        return m

    def hub(self) -> Msg:
        return self._one("hub")

    def own_msg(self, kind: str, session: str) -> Msg:
        return read_msg(self.xpath(self.label, kind, session), kind, self.pk)

    def roster(self) -> LeafRoster:
        if self._roster is None:
            info = self.secret["roster"]
            path = Path(self._roster_path or info["path"])
            if not path.exists():
                raise ProtocolError(f"명부 파일 {path} 를 찾을 수 없습니다. --roster 로 위치를 지정하세요")
            rd = load_roster(path, self.secret["norm"]["pivot_yy"], info["columns"])
            if rd.sha256 != info["sha256"]:
                raise ProtocolError("명부 파일이 setup 이후 바뀌었습니다(해시 불일치). 커밋한 명부와 다른 명부는 쓸 수 없습니다")
            self._roster = LeafRoster.build(self.seed, rd.records)
            if self._roster.root().hex() != self.secret["root"]:
                raise ProtocolError("명부 재구성 결과가 커밋과 다릅니다")
        return self._roster

    def _context(self, session: str):
        """우리·상대 setup, 중개인, 양측 1라운드를 읽고 검증한다."""
        s = self.session(session)
        own, peer, hub = self.own_setup(), self.peer_setup(), self.hub()
        if hub.msg_id.hex() != s["hub_id"] or peer.msg_id.hex() != s["peer_setup_id"]:
            raise VerificationError("교환 폴더의 상대 setup 또는 중개인이 round1 때와 다릅니다")
        own_r1 = self.own_msg("round1", session)
        peer_r1 = read_msg(self.xpath(peer.header["label"], "round1", session), "round1", peer.pk)
        sid, params = check_round1_pair(own_r1, peer_r1, own, peer, hub)
        if sid.hex() != s["sid"] or cjson(params) != cjson(s["params"]):
            raise VerificationError("상대 1라운드의 세션이 우리 세션과 다릅니다")
        return s, own, peer, hub, own_r1, peer_r1, sid, params

    # ------------------------------------------------------------ round1
    def round1(self, session: str, params: dict, peer_fingerprint: str | None = None,
               hub_fingerprint: str | None = None, peer_max_records: int | None = None) -> dict:
        self.reload()
        if not LABEL_RE.match(session or ""):
            raise ProtocolError("세션 이름은 영문·숫자·_·- 1~32자")
        if self.session(session, require=False):
            raise ProtocolError(f"세션 '{session}' 은 이미 시작되었습니다. 같은 키를 재사용하지 않도록 새 세션 이름을 쓰세요")
        own, peer, hub = self.own_setup(), self.peer_setup(), self.hub()
        ph = peer.header
        if ph.get("protocol") != PROTOCOL or hub.header.get("protocol") != PROTOCOL:
            raise VerificationError("상대 또는 중개인의 프로토콜 버전이 다릅니다")
        if ph["norm"] != own.header["norm"]:
            raise VerificationError(f"정규화 설정이 다릅니다 — 우리 {own.header['norm']} / 상대 {ph['norm']} "
                                    "(setup 의 --pivot-yy 를 맞추세요)")
        if hub.header["label"] in (self.label, ph["label"]):
            raise VerificationError("중개인 라벨이 당사자 라벨과 겹칩니다")
        if peer_fingerprint and fp_normalize(peer_fingerprint) != fp_normalize(fingerprint(peer.pk)):
            raise VerificationError("상대 서명키 지문이 사전에 확인한 값과 다릅니다 — 중단하세요")
        if hub_fingerprint and fp_normalize(hub_fingerprint) != fp_normalize(fingerprint(hub.pk)):
            raise VerificationError("중개인 서명키 지문이 사전에 확인한 값과 다릅니다 — 중단하세요")
        if peer_max_records is not None and ph["n_leaves"] > peer_max_records:
            raise VerificationError(f"상대 명부 크기 {ph['n_leaves']} 가 허용 상한 {peer_max_records} 를 넘습니다")
        sid = compute_sid(own, peer, hub, params, session)
        segs = layout(self.seed, sid, self.roster(), params)
        k = rand_scalar()
        nonce = os.urandom(32)
        with Engine(self.workers) as eng:
            payload = b"".join(eng.h2g_mul(sid, k, seg.tier, seg.keys) for seg in segs)
        meta = [{"tier": seg.tier, "count": len(seg.keys)} for seg in segs]
        header = {"type": "round1", "protocol": PROTOCOL, "label": self.label, "session": session,
                  "sid": sid.hex(), "setup_id": own.msg_id.hex(), "peer_setup_id": peer.msg_id.hex(),
                  "hub_id": hub.msg_id.hex(), "params": params, "psi_pk": mul_base(k).hex(),
                  "segments": meta, "nonce_commit": nonce_commit(nonce)}
        write_msg(self.xpath(self.label, "round1", session), header, payload, self.sk)
        self.sessions()[session] = {
            "params": params, "sid": sid.hex(), "psi_key": k.hex(), "nonce": nonce.hex(),
            "peer": ph["label"], "peer_setup_id": peer.msg_id.hex(), "hub": hub.header["label"],
            "hub_id": hub.msg_id.hex(), "stage": "round1", "started_at": now_iso()}
        self.save()
        return {"sid": sid.hex(), "segments": meta, "peer": ph["label"], "peer_n_leaves": ph["n_leaves"],
                "peer_fingerprint": fingerprint(peer.pk), "peer_display_name": ph.get("display_name", ""),
                "hub": hub.header["label"], "hub_display_name": hub.header.get("display_name", ""),
                "hub_fingerprint": fingerprint(hub.pk)}

    # ------------------------------------------------------------ round2
    def round2(self, session: str) -> dict:
        self.reload()
        s, own, peer, hub, own_r1, peer_r1, sid, params = self._context(session)
        if s.get("round2_for"):
            raise ProtocolError("이 세션은 이미 2라운드를 계산했습니다 — 같은 키로 다른 값을 다시 계산하지 않습니다")
        if "psi_key" not in s:
            raise ProtocolError("PSI 키가 폐기된 세션입니다")
        k = bytes.fromhex(s["psi_key"])
        U = peer_r1.payload
        check_distinct(U, peer_r1.header["segments"], "상대 1라운드")
        ctx = ctx_round2(sid, peer_r1.msg_id)
        with Engine(self.workers) as eng:
            try:
                D = eng.mul_all(k, U)
            except GroupError as e:
                raise VerificationError(f"상대 1라운드에 잘못된 군 원소가 있습니다: {e}") from None
            proof = dleq.batch_prove(eng, k, mul_base(k), U, D, ctx)
        enc_pk = bytes.fromhex(hub.header["enc_pk"])
        sealed = SealedBox(PublicKey(enc_pk)).encrypt(lp(R2_DST, sid, peer_r1.msg_id, bytes.fromhex(s["nonce"]), proof, D))
        header = {"type": "round2", "protocol": PROTOCOL, "label": self.label, "session": session, "sid": sid.hex(),
                  "peer_round1_id": peer_r1.msg_id.hex(), "hub_id": hub.msg_id.hex(),
                  "segments": peer_r1.header["segments"], "sealed_to": enc_pk.hex()}
        out = write_msg(self.xpath(self.label, "round2", session), header, sealed, self.sk)
        s["round2_for"] = peer_r1.msg_id.hex()
        s["stage"] = "round2"
        self.save()
        return {"send": out.path.name, "hub": hub.header["label"]}

    # ------------------------------------------------------------ finalize (검증 → 수락/거부 서명)
    def finalize(self, session: str) -> dict:
        """중개인 결과를 검증하고, 수락 또는 거부를 서명해 남긴다. 결과는 confirm 전까지 확정이 아니다."""
        self.reload()
        s, own, peer, hub, own_r1, peer_r1, sid, params = self._context(session)
        res = read_msg(self.xpath(hub.header["label"], "result", session), "result", hub.pk)
        try:
            out = self._verify_result(session, s, own, peer, hub, own_r1, peer_r1, sid, params, res)
        except VerificationError as e:
            self._write_accept(session, sid, res, "rejected", str(e))
            s["stage"] = "rejected"
            self.save()
            raise
        self._write_accept(session, sid, res, "accepted", None)
        write_private_json(self.sdir(session) / "result.json", out)
        s["stage"] = "finalized"
        s["result_id"] = res.msg_id.hex()
        self.save()
        return out

    def _verify_result(self, session, s, own, peer, hub, own_r1, peer_r1, sid, params, res) -> dict:
        labels = {self.label: own, peer.header["label"]: peer}
        r1s = {self.label: own_r1, peer.header["label"]: peer_r1}
        info = check_result(res, hub, labels, r1s)
        own_idx = info["order"].index(self.label)
        if info["nonces"][own_idx].hex() != s["nonce"]:
            raise VerificationError("중개인 결과에 실린 우리 감사 난수가 우리가 보낸 값과 다릅니다")
        r2_ids = res.header.get("round2_ids")
        if not isinstance(r2_ids, list) or len(r2_ids) != 2 or r2_ids[own_idx] != self.own_msg("round2", session).msg_id.hex():
            raise VerificationError("중개인 결과가 우리가 보낸 2라운드에 대한 것이 아닙니다")
        out = {"sid": sid.hex(), "mode": params["mode"], "tiers": params["tiers"], "counts": info["counts"],
               "audit_seed": info["audit_seed"].hex(), "peer": peer.header["label"], "hub": hub.header["label"],
               "result_id": res.msg_id.hex(), "pairs_sha256": res.header.get("pairs_sha256"),
               "confirmed": False, "finalized_at": now_iso()}
        if params["mode"] == "list":
            pairs_own = [(sg, (i, j)[own_idx], (i, j)[1 - own_idx], v) for sg, i, j, v in info["pairs"]]
            # 매칭 값 재확인: v 는 '상대 원소에 우리 키를 적용한 값'과 같아야 한다. 중개인이 가짜 쌍을 넣으면
            # 적어도 한쪽에서 이 확인이 실패하고, 그쪽의 거부가 confirm 단계에서 다른 쪽에도 전달된다.
            blob = b"".join(point_at(peer_r1, sg, pp) for sg, _, pp, _ in pairs_own)
            with Engine(self.workers) as eng:
                mine = eng.mul_all(bytes.fromhex(s["psi_key"]), blob) if blob else b""
            for n, (_, _, _, v) in enumerate(pairs_own):
                if mine[32 * n : 32 * n + 32] != v:
                    raise VerificationError("중개인 결과의 매칭 값이 우리 계산과 다릅니다 — 중개인 오류 또는 조작")
            out["pairs_own"] = [[sg, op, pp] for sg, op, pp, _ in pairs_own]
            out["persons"] = self._write_list_result(session, sid, params, pairs_own)
        return out

    def _write_accept(self, session: str, sid: bytes, res: Msg, status: str, reason: str | None) -> None:
        write_msg(self.xpath(self.label, "accept", session),
                  {"type": "accept", "protocol": PROTOCOL, "label": self.label, "session": session,
                   "sid": sid.hex(), "result_id": res.msg_id.hex(), "status": status, "reason": reason,
                   "counts": res.header.get("counts"), "pairs_sha256": res.header.get("pairs_sha256"),
                   "created_at": now_iso()}, b"", self.sk)

    # ------------------------------------------------------------ confirm (상호 수락 확인 → 확정)
    def confirm(self, session: str) -> dict:
        """상대도 같은 결과를 검증·수락했는지 확인한 뒤에만 결과를 확정한다."""
        self.reload()
        s = self.session(session)
        if s.get("stage") == "rejected":
            raise ProtocolError("우리 쪽에서 중개인 결과를 거부한 세션입니다 — 확정할 수 없습니다")
        rp = self.sdir(session) / "result.json"
        if not rp.exists():
            raise ProtocolError("finalize 를 먼저 실행하세요")
        result = json.loads(rp.read_text("utf-8"))
        peer = self.peer_setup()
        pa = read_msg(self.xpath(peer.header["label"], "accept", session), "accept", peer.pk).header
        if (pa.get("protocol") != PROTOCOL or pa.get("label") != peer.header["label"] or pa.get("session") != session
                or pa.get("sid") != s["sid"]):
            raise VerificationError("상대의 수락 메시지가 이 세션에 대한 것이 아닙니다")
        if pa.get("status") == "rejected":
            raise VerificationError(f"상대({peer.header['label']})가 중개인 결과를 거부했습니다 — 결과를 확정하지 마세요. "
                                    f"상대 사유: {pa.get('reason')}")
        if (pa.get("status") != "accepted" or pa.get("result_id") != result["result_id"]
                or pa.get("counts") != result["counts"] or pa.get("pairs_sha256") != result["pairs_sha256"]):
            raise VerificationError("상대가 수락한 결과가 우리가 받은 결과와 다릅니다 — 중개인에게 확인하세요")
        warnings = self._cross_session_check(session, result)
        pending = self.sdir(session) / "result.pending.csv"
        if pending.exists():
            pending.replace(self.sdir(session) / "result.csv")
        result["confirmed"] = True
        result["confirmed_at"] = now_iso()
        result["warnings"] = warnings
        write_private_json(rp, result)
        s["stage"] = "confirmed"
        self.save()
        return result

    def _cross_session_check(self, session: str, result: dict) -> list:
        """같은 상대·중개인·명부로 확정한 다른 세션과 등급별 매칭 수를 비교한다.
        1단계 건수와 2단계 매칭 수가 다르면 중개인(또는 상대 입력)이 단계 사이에 달라졌다는 뜻이다."""
        s = self.session(session)
        mine = {c["tier"]: c["matches"] for c in result["counts"]}
        out = []
        for name, other in self.sessions().items():
            if (name == session or other.get("stage") != "confirmed" or other.get("peer_setup_id") != s["peer_setup_id"]
                    or other.get("hub_id") != s["hub_id"]):
                continue
            op = self.sdir(name) / "result.json"
            if not op.exists():
                continue
            theirs = {c["tier"]: c["matches"] for c in json.loads(op.read_text("utf-8"))["counts"]}
            for t in set(mine) & set(theirs):
                if mine[t] != theirs[t]:
                    out.append(f"세션 '{name}' 의 {t} 매칭 {theirs[t]}건과 이번 {mine[t]}건이 다릅니다 — "
                               "중개인 계산 또는 상대 입력이 세션 사이에 달라졌을 수 있습니다")
        return out

    def _write_list_result(self, session: str, sid: bytes, params: dict, pairs_own: list) -> dict:
        roster = self.roster()
        segs = layout(self.seed, sid, roster, params)
        per_leaf: dict = {}
        for sg, op, pp, _ in pairs_own:
            seg = segs[sg]
            for leaf in roster.elements(seg.tier)[seg.keys[op]]:
                per_leaf.setdefault(leaf, {}).setdefault(seg.tier, []).append(f"{seg.tier}:{op}↔{pp}")
        rows = []
        for leaf, tiers in per_leaf.items():
            r = roster.records[leaf]
            grade = "정밀" if "strict" in tiers else "후보"
            where = "; ".join(x for t in params["tiers"] for x in tiers.get(t, []))
            rows.append((0 if grade == "정밀" else 1, r.name, grade, r.name, r.birth, r.phone,
                         ";".join(map(str, roster.lines[leaf])), where))
        rows.sort()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["등급", "이름", "생년월일", "휴대전화", "명부_줄번호", "매칭위치(등급:우리↔상대)"])
        for row in rows:
            w.writerow(row[2:])
        write_private_bytes(self.sdir(session) / "result.pending.csv", buf.getvalue().encode("utf-8-sig"))
        n_strict = sum(1 for r in rows if r[2] == "정밀")
        return {"strict": n_strict, "candidate": len(rows) - n_strict}

    # ------------------------------------------------------------ audit-open
    def audit_open(self, session: str, challenge: str = "random", positions: list | None = None) -> dict:
        self.reload()
        s = self.session(session)
        if "psi_key" not in s:
            raise ProtocolError("PSI 키가 이미 폐기되어 감사 응답을 만들 수 없습니다")
        params = s["params"]
        sid = bytes.fromhex(s["sid"])
        own_r1 = self.own_msg("round1", session)
        rp = self.sdir(session) / "result.json"
        if not rp.exists():
            raise ProtocolError("finalize 를 먼저 실행하세요")
        result = json.loads(rp.read_text("utf-8"))
        if not result.get("confirmed"):
            raise ProtocolError("양당 수락이 확인된(confirm) 결과만 감사할 수 있습니다")
        if challenge == "random":
            pos = challenge_positions(bytes.fromhex(result["audit_seed"]), own_r1, params["audit_k"])
        elif challenge == "matched":
            if params["mode"] != "list":
                raise ProtocolError("매칭 감사는 명단 모드에서만 가능합니다")
            pos = sorted({(sg, op) for sg, op, _ in result["pairs_own"]})
        elif challenge == "custom":
            pos = sorted({(int(a), int(b)) for a, b in (positions or [])})
        else:
            raise ProtocolError(f"알 수 없는 감사 종류: {challenge}")
        k = bytes.fromhex(s["psi_key"])
        K = mul_base(k)
        roster = self.roster()
        segs = layout(self.seed, sid, roster, params)
        tree = merkle.Tree(roster.leaves)
        entries = []
        for sg, p in pos:
            if not (0 <= sg < len(segs) and 0 <= p < len(segs[sg].keys)):
                raise ProtocolError(f"범위를 벗어난 위치: {(sg, p)}")
            seg = segs[sg]
            key = seg.keys[p]
            leaf = roster.elements(seg.tier)[key][0]
            U = point_at(own_r1, sg, p)
            entries.append({
                "segment": sg, "pos": p, "tier": seg.tier, "leaf_index": leaf,
                "record": roster.records[leaf].as_dict(), "salt": roster.salts[leaf].hex(),
                "merkle_path": [h.hex() for h in tree.path(leaf)],
                "dleq": dleq.prove(k, G, K, element_point(sid, seg.tier, key), U,
                                   ctx_audit(sid, own_r1.msg_id, sg, p)).hex()})
        doc = {"type": "audit-opening", "protocol": PROTOCOL, "label": self.label, "session": session,
               "sid": sid.hex(), "round1_id": own_r1.msg_id.hex(), "challenge": challenge,
               "created_at": now_iso(), "entries": entries}
        return sign_json(doc, self.sk)

    # ------------------------------------------------------------ destroy-key
    def destroy_key(self, session: str) -> None:
        self.reload()
        s = self.session(session)
        s.pop("psi_key", None)
        s["key_destroyed_at"] = now_iso()
        self.save()
