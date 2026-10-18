"""감사인·참관인용 검증.

1) load_public / verify_transcript: 공개 메시지(setup·중개인·1라운드·결과·수락)만으로 서명과 세션 연결,
   감사 난수, 매칭 결과 형식, 양당의 수락 여부를 검증한다. 중개인 작업 폴더가 있으면 봉인된 2라운드까지 열어
   증명과 결과 전체를 다시 계산해 배포된 결과와 대조한다.
2) audit_verify: 한쪽 당이 감사인에게만 낸 감사 응답(레코드 공개)을 검증한다.
   - 양당이 모두 같은 결과를 수락(accept)한 경우에만 감사한다.
   - 감사 범위는 감사인이 정한다: 무작위(감사 난수로 결정) / 매칭(중개인 결과의 매칭 위치 전부) /
     지정(감사인이 준 위치 목록). 응답자가 적어 낸 범위는 믿지 않는다.
   - 암호 검증: 머클 경로(사전 커밋한 명부에 있었는가) + DLEQ(1라운드 값이 그 레코드에서 나왔는가)
   - 실당원 확인: 증빙 명부(입당원서·당비 기록 등에서 뽑은 CSV)와 대조하거나 수작업 확인 목록으로 출력
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from pathlib import Path

from . import PROTOCOL, dleq, merkle
from .group import G, element_point
from .messages import Msg, read_msg, verify_json
from .normalize import TIER_KO, Record, load_roster
from .protocol import (Hub, ProtocolError, VerificationError, challenge_positions, check_result, check_round1_pair,
                       ctx_audit, encode_pairs, point_at)
from .util import now_iso


@dataclass
class PublicView:
    session: str
    sid: bytes
    params: dict
    order: list
    setups: dict
    hub: Msg
    r1: dict
    result: dict | None
    result_msg: Msg | None
    accepts: dict  # 라벨 → 수락 메시지 헤더(없으면 None)

    def both_accepted(self) -> bool:
        return self.result_msg is not None and all(
            a is not None and a.get("status") == "accepted" and a.get("result_id") == self.result_msg.msg_id.hex()
            for a in self.accepts.values())


def load_public(exchange, session: str) -> PublicView:
    exchange = Path(exchange)
    setups = {}
    for p in sorted(exchange.glob("*.setup.msg")):
        m = read_msg(p, "setup")
        if f"{m.header['label']}.setup.msg" != p.name:
            raise ProtocolError(f"{p.name}: 파일 이름과 내부 라벨이 다릅니다")
        setups[m.header["label"]] = m
    if len(setups) != 2:
        raise ProtocolError(f"교환 폴더에 두 당의 setup 메시지가 있어야 합니다 (현재 {len(setups)}개)")
    hubs = sorted(exchange.glob("*.hub.msg"))
    if len(hubs) != 1:
        raise ProtocolError(f"교환 폴더에 중개인 메시지(*.hub.msg)가 정확히 하나 있어야 합니다 (현재 {len(hubs)}개)")
    hub = read_msg(hubs[0], "hub")
    order = sorted(setups, key=lambda l: setups[l].msg_id)
    r1 = {}
    for l in order:
        p = exchange / f"{l}.{session}.round1.msg"
        if not p.exists():
            raise ProtocolError(f"{p.name} 가 없습니다")
        r1[l] = read_msg(p, "round1", setups[l].pk)
    sid, params = check_round1_pair(r1[order[0]], r1[order[1]], setups[order[0]], setups[order[1]], hub)
    rp = exchange / f"{hub.header['label']}.{session}.result.msg"
    res_msg = read_msg(rp, "result", hub.pk) if rp.exists() else None
    result = check_result(res_msg, hub, setups, r1) if res_msg else None
    accepts = {}
    for l in order:
        p = exchange / f"{l}.{session}.accept.msg"
        h = read_msg(p, "accept", setups[l].pk).header if p.exists() else None
        if h is not None and (h.get("sid") != sid.hex() or h.get("session") != session or h.get("label") != l):
            raise VerificationError(f"{l}의 수락 메시지가 이 세션에 대한 것이 아닙니다")
        accepts[l] = h
    return PublicView(session, sid, params, order, setups, hub, r1, result, res_msg, accepts)


def verify_transcript(exchange, session: str, hub_work=None, workers: int | None = None) -> tuple:
    """(PublicView, 문제 목록). hub_work 가 있으면 2라운드를 열어 전체를 재계산·대조한다."""
    V = load_public(exchange, session)
    issues = []
    for l, a in V.accepts.items():
        if a is not None and a.get("status") == "rejected":
            issues.append(f"{l}가 중개인 결과를 거부했습니다: {a.get('reason')}")
        elif a is not None and V.result_msg is not None and a.get("result_id") != V.result_msg.msg_id.hex():
            issues.append(f"{l}가 수락한 결과가 배포된 결과와 다릅니다")
    if hub_work is not None:
        if V.result is None:
            issues.append("중개인 결과가 아직 없습니다")
        else:
            c = Hub(hub_work, exchange, workers).compute(session)
            h = V.result_msg.header
            if [x["matches"] for x in V.result["counts"]] != c["counts"]:
                issues.append("배포된 건수가 재계산 결과와 다릅니다")
            if V.params["mode"] == "list" and h["pairs_sha256"] != hashlib.sha256(encode_pairs(c["pairs"])).hexdigest():
                issues.append("배포된 매칭 쌍이 재계산 결과와 다릅니다")
            if V.result["audit_seed"] != c["audit_seed"]:
                issues.append("감사 난수가 재계산 결과와 다릅니다")
    return V, issues


def audit_verify(exchange, session: str, opening_path, challenge: str, positions=None, evidence=None,
                 evidence_columns=None) -> tuple:
    """(보고서 dict, 감사 응답 dict). 보고서에는 레코드 내용이 들어가지 않는다."""
    V = load_public(exchange, session)
    if V.result is None:
        raise ProtocolError("중개인 결과(result.msg)가 있어야 감사 범위를 정할 수 있습니다")
    if not V.both_accepted():
        state = ", ".join(f"{l}: {(a or {}).get('status', '수락 메시지 없음')}" for l, a in V.accepts.items())
        raise ProtocolError(f"양당이 모두 같은 결과를 수락한 경우에만 감사합니다 ({state})")
    doc = json.loads(Path(opening_path).read_text("utf-8"))
    owner = doc.get("label")
    if owner not in V.setups:
        raise ProtocolError(f"감사 응답의 당사자 '{owner}' 가 이 전사본에 없습니다")
    verify_json(doc, V.setups[owner].pk)
    owner_r1 = V.r1[owner]
    if (doc.get("type") != "audit-opening" or doc.get("protocol") != PROTOCOL or doc.get("sid") != V.sid.hex()
            or doc.get("session") != session or doc.get("round1_id") != owner_r1.msg_id.hex()):
        raise VerificationError("감사 응답이 이 세션의 1라운드에 대한 것이 아닙니다")
    if doc.get("challenge") != challenge:
        raise VerificationError(f"요청한 감사 종류({challenge})와 응답의 종류({doc.get('challenge')})가 다릅니다")
    if challenge == "random":
        expected = set(challenge_positions(V.result["audit_seed"], owner_r1, V.params["audit_k"]))
    elif challenge == "matched":
        if V.params["mode"] != "list":
            raise ProtocolError("매칭 감사는 명단 모드에서만 가능합니다")
        idx = 1 if owner == V.order[0] else 2
        expected = {(p[0], p[idx]) for p in V.result["pairs"]}
    elif challenge == "custom":
        if positions is None:
            raise ProtocolError("지정 감사(custom)에는 감사인이 정한 위치 목록이 필요합니다")
        expected = {(int(a), int(b)) for a, b in positions}
    else:
        raise ProtocolError(f"알 수 없는 감사 종류: {challenge}")

    hdr = V.setups[owner].header
    pivot = hdr["norm"]["pivot_yy"]
    root = bytes.fromhex(hdr["root"])
    n_leaves = hdr["n_leaves"]
    K = bytes.fromhex(owner_r1.header["psi_pk"])
    segs = owner_r1.header["segments"]
    evid = set(load_roster(evidence, pivot, evidence_columns).records) if evidence else None

    entries = doc.get("entries") or []
    opened, results = [], []
    for e in entries:
        r = {"segment": e.get("segment"), "pos": e.get("pos")}
        try:
            si, p = int(e["segment"]), int(e["pos"])
            opened.append((si, p))
            if not (0 <= si < len(segs) and 0 <= p < segs[si]["count"]):
                raise ValueError("위치가 범위를 벗어남")
            tier = segs[si]["tier"]
            if e.get("tier") != tier:
                raise ValueError("등급 불일치")
            rec = Record.from_dict(e["record"])
            if not rec.is_normalized(pivot):
                raise ValueError("정규화되지 않은 레코드")
            key = rec.key(tier)
            if key is None:
                raise ValueError("이 등급의 키를 만들 수 없는 레코드")
            leaf = merkle.leaf_hash(bytes.fromhex(e["salt"]), rec.to_bytes())
            if not merkle.verify_path(root, n_leaves, int(e["leaf_index"]), leaf, [bytes.fromhex(h) for h in e["merkle_path"]]):
                raise ValueError("머클 경로 불일치 — 사전 커밋한 명부에 없던 레코드")
            if not dleq.verify(bytes.fromhex(e["dleq"]), G, K, element_point(V.sid, tier, key), point_at(owner_r1, si, p),
                               ctx_audit(V.sid, owner_r1.msg_id, si, p)):
                raise ValueError("DLEQ 불일치 — 1라운드 값이 이 레코드에서 나오지 않음")
            r["tier"] = tier
            if evid is not None:
                r["genuine"] = rec in evid
            r["crypto"] = "ok"
        except (KeyError, TypeError, ValueError) as ex:
            r["crypto"] = f"실패: {ex}"
        results.append(r)

    dup = len(opened) != len(set(opened))
    missing = sorted(expected - set(opened))
    extra = sorted(set(opened) - expected)
    crypto_fail = [r for r in results if r["crypto"] != "ok"]
    not_genuine = [r for r in results if r.get("genuine") is False]
    pending = [r for r in results if r["crypto"] == "ok" and "genuine" not in r]
    crypto_ok = not (missing or extra or crypto_fail or dup)
    report = {
        "type": "audit-report", "protocol": PROTOCOL, "session": session, "sid": V.sid.hex(), "owner": owner,
        "challenge": challenge, "verified_at": now_iso(), "expected_positions": len(expected), "opened": len(entries),
        "missing": [list(x) for x in missing], "extra": [list(x) for x in extra], "duplicate_entries": dup,
        "crypto_failures": len(crypto_fail),
        "genuineness": "evidence" if evid is not None else "pending-manual",
        "not_genuine": len(not_genuine), "pending_manual": len(pending),
        "crypto_passed": crypto_ok, "passed": crypto_ok and evid is not None and not not_genuine,
        "entries": results,
    }
    return report, doc


def worklist_csv(doc: dict, report: dict) -> bytes:
    """감사인 수작업 확인용 목록(레코드 포함 — 감사인 외 반출 금지)."""
    status = {(r["segment"], r["pos"]): r for r in report["entries"]}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["세그먼트", "위치", "등급", "이름", "생년월일", "휴대전화", "암호검증", "증빙대조"])
    for e in doc.get("entries") or []:
        r = status.get((e.get("segment"), e.get("pos")), {})
        rec = e.get("record") or {}
        g = r.get("genuine")
        w.writerow([e.get("segment"), e.get("pos"), TIER_KO.get(e.get("tier"), e.get("tier")), rec.get("name"),
                    rec.get("birth"), rec.get("phone"), r.get("crypto"),
                    "미확인" if g is None else ("일치" if g else "증빙 없음")])
    return buf.getvalue().encode("utf-8-sig")


def detection_probability(n: int, m: int, k: int) -> float:
    """원소 n개 중 m개가 부정일 때 무작위 k개 감사로 하나 이상 잡을 확률(비복원)."""
    if m <= 0:
        return 0.0
    if k >= n:
        return 1.0
    miss = 1.0
    for i in range(k):
        miss *= max(0.0, (n - m - i) / (n - i))
    return 1.0 - miss
