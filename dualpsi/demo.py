"""가상 명부로 전체 절차와 공격 탐지를 시연한다.  실행: python -m dualpsi demo

데이터는 전부 무작위로 만든 가상 인물이며 실제 당원과 무관하다.
세 참여자(DP, RKP, 중개인)가 한 교환 폴더를 함께 쓰는 것으로 '파일 전달'을 흉내 낸다
(실제로는 각자 사본을 주고받는다. 2라운드는 중개인에게 봉인되어 있어 섞여 있어도 안전하다).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import random
import shutil
import tempfile
import time
from datetime import date, timedelta
from pathlib import Path

from nacl.public import PrivateKey, PublicKey, SealedBox

from . import dleq
from .audit import audit_verify, detection_probability, verify_transcript
from .group import Engine, element_point, mul_base, split_points
from .messages import read_msg, write_msg
from .normalize import TIERS, default_pivot, load_roster
from .protocol import (R2_DST, Hub, Party, VerificationError, ctx_round2, encode_pairs, hub_init, make_params,
                       open_round2, seg_ranges, setup)
from .util import lp

SURNAMES = [("김", 215), ("이", 147), ("박", 84), ("최", 47), ("정", 43), ("강", 24), ("조", 21), ("윤", 21),
            ("장", 20), ("임", 17), ("한", 15), ("오", 15), ("서", 14), ("신", 14), ("권", 14), ("황", 14),
            ("안", 13), ("송", 13), ("전", 11), ("홍", 11), ("유", 11), ("고", 9), ("문", 9), ("양", 9),
            ("손", 9), ("배", 8), ("백", 7), ("허", 6), ("남", 6), ("심", 5), ("노", 4), ("하", 4), ("곽", 4),
            ("성", 4), ("차", 4), ("주", 4), ("우", 4), ("구", 4), ("민", 3), ("남궁", 1), ("황보", 1), ("제갈", 1)]
GIVEN1 = "민서지수현준영성진호은혜정동우재상경미희승태연윤도하유주예시아건채소다원선종석용"
GIVEN2 = "준수민현우진호영희숙자서연윤아은빈하린율원혁석철훈규성재환식미경정"

A_HEADER = ["이름", "생년월일", "휴대전화"]
B_HEADER = ["성명", "생일", "연락처"]


# ---------------------------------------------------------------- 가상 데이터

def _new_phone(rng, used):
    while True:
        p = "010" + f"{rng.randrange(10 ** 8):08d}"
        if p not in used:
            used.add(p)
            return p


def _people(rng, n, used):
    surn, weights = zip(*SURNAMES)
    start = date(1940, 1, 1)
    span = (date(2010, 10, 1) - start).days
    return [{"name": rng.choices(surn, weights)[0] + rng.choice(GIVEN1) + rng.choice(GIVEN2),
             "birth": start + timedelta(days=rng.randrange(span)),
             "phone": _new_phone(rng, used)} for _ in range(n)]


def _dash(ph):
    return f"{ph[:3]}-{ph[3:7]}-{ph[7:]}" if ph else ""


def _fmt_a(p):
    return [p["name"], p["birth"].isoformat(), _dash(p["phone"])]


def _fmt_b(rng, p):
    name = p["name"]
    r = rng.random()
    if r < 0.1:
        name = name[0] + " " + name[1:]
    elif r < 0.2:
        name = f" {name} "
    b = p["birth"]
    r = rng.random()
    if r < 0.4:
        bs = b.strftime("%Y%m%d")
    elif r < 0.6:
        bs = f"{b.year}.{b.month}.{b.day}"
    elif r < 0.8:
        bs = b.strftime("%y%m%d")
    elif r < 0.9:
        bs = f"{b.year}년 {b.month}월 {b.day}일"
    else:
        bs = b.strftime("%y.%m.%d")
    ph = p["phone"]
    r = rng.random()
    if not ph:
        ps = ""
    elif r < 0.4:
        ps = ph
    elif r < 0.6:
        ps = f"{ph[:3]} {ph[3:7]} {ph[7:]}"
    elif r < 0.8:
        ps = f"+82 {ph[1:3]}-{ph[3:7]}-{ph[7:]}"
    elif r < 0.9:
        ps = ph[1:]  # 엑셀이 앞자리 0 을 지운 경우
    else:
        ps = _dash(ph)
    return [name, bs, ps]


def _write_csv(path, header, rows, encoding):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    Path(path).write_bytes(buf.getvalue().encode(encoding))


def make_dataset(d: Path, size_a: int, size_b: int, n_dual: int, seed: int = 20261017) -> dict:
    """A(UTF-8, 정형 표기)와 B(CP949, 제각각 표기) 가상 명부를 만든다."""
    rng = random.Random(seed)
    used: set = set()
    pool = _people(rng, size_a + size_b, used)
    dual = pool[:n_dual]
    a_only = pool[n_dual:size_a]
    b_only = pool[size_a:size_a + size_b - n_dual]
    n_changed, n_nophone = n_dual * 15 // 100, n_dual * 5 // 100
    b_dual = []
    for i, p in enumerate(dual):
        q = dict(p)
        if i < n_changed:
            q["phone"] = _new_phone(rng, used)
        elif i < n_changed + n_nophone:
            q["phone"] = ""
        b_dual.append(q)
    n_hom = min(20, len(a_only), len(b_only))
    for i in range(n_hom):  # 동명이인: 이름·생년월일이 같은 다른 사람
        b_only[i] = {"name": a_only[i]["name"], "birth": a_only[i]["birth"], "phone": _new_phone(rng, used)}
    a_people = dual + a_only
    rng.shuffle(a_people)
    a_rows = [_fmt_a(p) for p in a_people]
    n_dupe, n_bad = min(30, len(a_people)), 15
    a_rows += [_fmt_b(rng, p) for p in rng.sample(a_people, n_dupe)]  # 같은 사람 중복 입력
    a_rows += [[rng.choice("김이박최") + "미상", "미상", ""] for _ in range(n_bad)]  # 생년월일 오류
    rng.shuffle(a_rows)
    b_people = b_dual + b_only
    rng.shuffle(b_people)
    b_rows = [_fmt_b(rng, p) for p in b_people]
    d.mkdir(parents=True, exist_ok=True)
    _write_csv(d / "a.csv", A_HEADER, a_rows, "utf-8-sig")
    _write_csv(d / "b.csv", B_HEADER, b_rows, "cp949")
    inject = [_fmt_a(p) for p in b_only[n_hom:n_hom + 300]]  # 공격 시나리오용: 상대 당원 300명
    _write_csv(d / "a_injected.csv", A_HEADER, a_rows + inject, "utf-8-sig")
    return {"a_rows": len(a_rows), "b_rows": len(b_rows), "dual": n_dual, "changed": n_changed,
            "nophone": n_nophone, "homonym": n_hom, "dupes": n_dupe, "bad": n_bad, "injected": len(inject)}


def plaintext_truth(a_csv, b_csv, pivot) -> dict:
    """데모에서만 가능한 평문 대조(정답지)."""
    ra = load_roster(a_csv, pivot).records
    rb = load_roster(b_csv, pivot).records
    out = {}
    for t in TIERS:
        ka = {r.key(t) for r in ra if r.key(t)}
        kb = {r.key(t) for r in rb if r.key(t)}
        out[t] = len(ka & kb)
    kb_s = {r.key("strict") for r in rb if r.key("strict")}
    kb_l = {r.key("loose") for r in rb}
    strict_p = sum(1 for r in ra if r.key("strict") in kb_s)
    cand_p = sum(1 for r in ra if r.key("loose") in kb_l and r.key("strict") not in kb_s)
    out["persons"] = {"strict": strict_p, "candidate": cand_p}
    return out


# ---------------------------------------------------------------- 부정행위 흉내 (테스트·시연용)

def _resign(path: Path, sk, payload: bytes | None = None, update: dict | None = None):
    m = read_msg(path)
    h = {k: v for k, v in m.header.items() if k not in ("sig", "sig_pk", "payload_len", "payload_sha256")}
    h.update(update or {})
    return write_msg(path, h, m.payload if payload is None else payload, sk)


def forge_round2(party: Party, session: str, mutate):
    """부정한 당사자: 2라운드 값을 바꾼 뒤 자기 키로 증명을 새로 만들고 다시 봉인·서명한다.
    서명·형식은 완벽하므로 수학적 검증만으로 잡히는지 확인하는 용도."""
    party.reload()
    s = party.session(session)
    k = bytes.fromhex(s["psi_key"])
    sid = bytes.fromhex(s["sid"])
    peer = party.peer_setup()
    peer_r1 = read_msg(party.xpath(peer.header["label"], "round1", session), "round1", peer.pk)
    with Engine(party.workers) as eng:
        pts = split_points(eng.mul_all(k, peer_r1.payload))
        mutate(pts)
        D = b"".join(pts)
        proof = dleq.batch_prove(eng, k, mul_base(k), peer_r1.payload, D, ctx_round2(sid, peer_r1.msg_id))
    path = party.xpath(party.label, "round2", session)
    enc_pk = bytes.fromhex(read_msg(path).header["sealed_to"])
    sealed = SealedBox(PublicKey(enc_pk)).encrypt(lp(R2_DST, sid, peer_r1.msg_id, bytes.fromhex(s["nonce"]), proof, D))
    return _resign(path, party.sk, sealed)


def plant_probes(party: Party, session: str, targets: list) -> list:
    """부정한 당사자: 1라운드의 정밀 원소 일부를 '자기 키를 쓰지 않은' 떠보기 값 H_sid(추측)으로 바꾼다.
    직접 교환 구조였다면 상대가 돌려준 k_상대·H(추측) 을 상대 1라운드와 비교해 명부를 몰래 조회할 수 있다."""
    party.reload()
    sid = bytes.fromhex(party.session(session)["sid"])
    path = party.xpath(party.label, "round1", session)
    m = read_msg(path)
    pts = split_points(m.payload)
    a0, _ = seg_ranges(m.header["segments"])[0]
    slots = list(range(a0, a0 + len(targets)))
    for slot, key in zip(slots, targets):
        pts[slot] = element_point(sid, "strict", key)
    _resign(path, party.sk, b"".join(pts))
    return slots


def forge_hub_result(hub: Hub, session: str) -> None:
    """부정한 중개인: 실제로는 매칭되지 않은 가짜 쌍 하나를 결과에 끼워 넣는다.
    가짜 값은 '첫째 당의 키를 적용한 둘째 당 원소'로 골라 첫째 당의 재확인은 통과하게 만든다."""
    c = hub.compute(session)
    a, b = c["order"]
    r1a, r1b = c["r1"][a], c["r1"][b]
    used_a = {(s, i) for s, i, _, _ in c["pairs"]}
    used_b = {(s, j) for s, _, j, _ in c["pairs"]}
    i = next(x for x in range(r1a.header["segments"][0]["count"]) if (0, x) not in used_a)
    j = next(x for x in range(r1b.header["segments"][0]["count"]) if (0, x) not in used_b)
    D_b = open_round2(c["r2"][a], hub.enc_sk)[4]  # a 가 b 원소에 키를 적용한 값
    fake = (0, i, j, D_b[32 * j : 32 * j + 32])
    payload = encode_pairs(c["pairs"] + [fake])
    path = hub.xpath(hub.label, "result", session)
    counts = read_msg(path).header["counts"]
    counts[0]["matches"] += 1
    _resign(path, hub.sk, payload, {"pairs_sha256": hashlib.sha256(payload).hexdigest(), "counts": counts})


# ---------------------------------------------------------------- 실행 보조

class _Clock:
    def __init__(self):
        self.t = time.perf_counter()

    def lap(self) -> str:
        now = time.perf_counter()
        s, self.t = now - self.t, now
        return f"{s:.1f}초"


def _run(pa: Party, pb: Party, hub: Hub, session: str, params: dict, after_round1=None, after_round2=None):
    pa.round1(session, params)
    pb.round1(session, params)
    if after_round1:
        after_round1()
    pa.round2(session)
    pb.round2(session)
    if after_round2:
        after_round2()
    hub.mediate(session)


def _write_opening(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc, ensure_ascii=False), "utf-8")
    return path


def run_demo(size_a: int = 12000, size_b: int = 5000, n_dual: int = 300, workers: int | None = None,
             keep: str | None = None, log=print) -> dict:
    root = Path(keep) if keep else Path(tempfile.mkdtemp(prefix="dualpsi-demo-"))
    if keep and root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    pivot = default_pivot()
    try:
        clock = _Clock()
        log("=" * 66)
        log(" dualpsi 데모 — 가상 명부로 이중당적자 산출 전 과정을 시연합니다")
        log("=" * 66)
        info = make_dataset(root / "data", size_a, size_b, n_dual)
        truth = plaintext_truth(root / "data/a.csv", root / "data/b.csv", pivot)
        log(f"\n[데이터] 가상 명부 생성 ({clock.lap()})")
        log(f"  DP(더불어민주당 측, 가상) {info['a_rows']:,}행  UTF-8 / 정형 표기")
        log(f"  RKP(조국혁신당 측, 가상) {info['b_rows']:,}행  CP949 / 표기 제각각(+82, 800102, 홍 길동 …)")
        log(f"  심어 둔 이중당적자 {info['dual']}명 (그중 번호 변경 {info['changed']}명, RKP 쪽 번호 없음 {info['nophone']}명)")
        log(f"  동명이인(다른 사람) {info['homonym']}쌍, DP 중복 입력 {info['dupes']}행, 생년월일 오류 {info['bad']}행")

        X = root / "exchange"
        hi = hub_init(root / "work_HUB", X, "HUB", "중립 중개인(가상)")
        sa = setup(root / "work_DP", X, "DP", root / "data/a.csv", "더불어민주당(가상)", pivot_yy=pivot)
        sb = setup(root / "work_RKP", X, "RKP", root / "data/b.csv", "조국혁신당(가상)", pivot_yy=pivot)
        log(f"\n[1] 준비 — 중개인 키 공개, 각 당이 명부를 정규화하고 머클 루트로 사전 커밋 ({clock.lap()})")
        log(f"  HUB: 지문 {hi['fingerprint']}")
        for s in (sa, sb):
            log(f"  {s['label']}: 유효 {s['n_leaves']:,}명 · 제외 {s['rejects']}행 · 중복 병합 {s['duplicates']}행 "
                f"· 인코딩 {s['encoding']} · 지문 {s['fingerprint']}")
        A = Party(root / "work_DP", X, workers)
        B = Party(root / "work_RKP", X, workers)
        Hb = Hub(root / "work_HUB", X, workers)

        # ---------------- 1단계: 건수
        _run(A, B, Hb, "phase1", make_params("count", TIERS, audit_k=200, purpose="데모 1단계"))
        ra = A.finalize("phase1")
        B.finalize("phase1")
        A.confirm("phase1")
        B.confirm("phase1")
        c = {x["tier"]: x["matches"] for x in ra["counts"]}
        ok1 = c["strict"] == truth["strict"] and c["loose"] == truth["loose"]
        log(f"\n[2] 1단계 · 건수 모드 — 양당 모두 건수만 받음 ({clock.lap()})")
        log(f"  정밀 일치 {c['strict']}건 · 이름+생년월일 일치 {c['loose']}건")
        log(f"  평문 대조 정답 {truth['strict']} / {truth['loose']} → {'일치 ✓' if ok1 else '불일치 ✗'}")

        # ---------------- 2단계: 명단
        _run(A, B, Hb, "phase2", make_params("list", TIERS, audit_k=200, purpose="데모 2단계"))
        ra = A.finalize("phase2")
        rb = B.finalize("phase2")
        ca, cb = A.confirm("phase2"), B.confirm("phase2")
        per = ra["persons"]
        _, issues = verify_transcript(X, "phase2", root / "work_HUB", workers)
        ok2 = (per == truth["persons"] and not issues and len(ra["pairs_own"]) == len(rb["pairs_own"])
               and ca["confirmed"] and cb["confirmed"])
        log(f"\n[3] 2단계 · 명단 모드 — 각 당은 자기 당원 중 해당자만 알게 됨 ({clock.lap()})")
        log(f"  DP 측 결과: 정밀 {per['strict']}명 · 후보 {per['candidate']}명 "
            f"(후보 = 번호 변경 {info['changed']} + 번호 없음 {info['nophone']} + 동명이인 {info['homonym']})")
        log(f"  평문 대조 정답 정밀 {truth['persons']['strict']} · 후보 {truth['persons']['candidate']} → "
            f"{'일치 ✓' if ok2 else '불일치 ✗'}")
        log(f"  양당이 매칭 값 {len(ra['pairs_own'])}개를 각자 자기 키로 재확인하고 서로의 수락을 확인 ✓ · "
            f"전사본 재계산 {'일치 ✓' if not issues else '불일치 ✗'}")
        log("  DP 측 해당자 명단(result.csv) 앞부분:")
        with open(A.sdir("phase2") / "result.csv", encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
        for row in rows[1:4]:
            log(f"    {row[0]} | {row[1]} | {row[2]} | {row[3]} | 줄 {row[4]}")
        audits = {}
        for who, P, ev in (("DP", A, root / "data/a.csv"), ("RKP", B, root / "data/b.csv")):
            for ch in ("random", "matched"):
                op = _write_opening(root / f"audit_{who}_{ch}.json", P.audit_open("phase2", ch))
                audits[(who, ch)], _ = audit_verify(X, "phase2", op, ch, evidence=ev)
        okA = all(r["passed"] for r in audits.values())
        log(f"  감사: 무작위 {audits[('DP', 'random')]['opened']}건씩 · 매칭 {audits[('DP', 'matched')]['opened']}건씩 공개 → "
            f"머클·DLEQ·증빙 대조 {'모두 통과 ✓' if okA else '실패 ✗'} ({clock.lap()})")

        log("\n[4] 공격 시나리오")
        # ---------------- 4-1 2라운드 값 조작
        def hide_one(pts):
            pts[0] = mul_base((7).to_bytes(32, "little"))

        try:
            _run(A, B, Hb, "atk-tamper", make_params("list", TIERS),
                 after_round2=lambda: forge_round2(B, "atk-tamper", hide_one))
            det1 = False
        except VerificationError:
            det1 = True
        log(f"  4-1 RKP가 2라운드 값 1개를 바꾸고 자기 키로 증명을 다시 만듦(특정인 숨기기) → "
            f"{'중개인의 DLEQ 배치 검증에서 탐지 ✓' if det1 else '탐지 실패 ✗'} ({clock.lap()})")

        # ---------------- 4-2 떠보기 (직접 교환 구조의 치명적 약점)
        ra_ = load_roster(root / "data/a.csv", pivot).records
        rb_ = load_roster(root / "data/b.csv", pivot).records
        a_keys = {r.key("strict") for r in ra_ if r.key("strict")}
        b_keys = {r.key("strict") for r in rb_ if r.key("strict")}
        targets = sorted(a_keys - b_keys)[:8] + [f"가짜{i}|19700101|0101234{i:04d}" for i in range(8)]
        slots = []
        _run(A, B, Hb, "atk-probe", make_params("list", TIERS, audit_k=200),
             after_round1=lambda: slots.extend(plant_probes(B, "atk-probe", targets)))
        A.finalize("atk-probe")
        rbp = B.finalize("atk-probe")
        A.confirm("atk-probe")
        B.confirm("atk-probe")
        hit = sum(1 for sg, op, _ in rbp["pairs_own"] if sg == 0 and op in slots)
        try:
            open_round2(read_msg(A.xpath("DP", "round2", "atk-probe")), PrivateKey.generate())
            sealed_ok = False
        except VerificationError:
            sealed_ok = True
        op = _write_opening(root / "audit_probe.json", B.audit_open("atk-probe", "random"))
        rep_p, _ = audit_verify(X, "atk-probe", op, "random", evidence=root / "data/b.csv")
        n_el = sum(sg["count"] for sg in B.own_msg("round1", "atk-probe").header["segments"])
        log(f"  4-2 RKP가 1라운드에 키를 쓰지 않은 떠보기 원소 {len(targets)}개(DP 당원 8 + 가상 인물 8)를 섞음")
        log(f"      DP의 2라운드는 중개인에게 봉인 → RKP가 열기 시도 {'실패 ✓' if sealed_ok else '성공 ✗'}"
            f" · 중개인 결과에 떠보기 매칭 {hit}건 → RKP가 알아낸 것 없음 {'✓' if hit == 0 else '✗'}")
        log(f"      무작위 감사 200건: 감사 응답 불일치 {rep_p['crypto_failures']}건 "
            f"(떠보기가 표본에 걸릴 이론 확률 {detection_probability(n_el, len(targets), 200) * 100:.0f}% — "
            f"걸리지 않아도 얻는 정보는 없음) ({clock.lap()})")

        # ---------------- 4-3 명부 끼워넣기
        X2 = root / "exchange_inject"
        X2.mkdir()
        for name in ("RKP.setup.msg", "HUB.hub.msg"):
            shutil.copy(X / name, X2 / name)
        setup(root / "work_DP_cheat", X2, "DP", root / "data/a_injected.csv", "더불어민주당(가상·부정)", pivot_yy=pivot)
        A2 = Party(root / "work_DP_cheat", X2, workers)
        B2 = Party(root / "work_RKP", X2, workers)
        H2 = Hub(root / "work_HUB", X2, workers)
        _run(A2, B2, H2, "atk-inject", make_params("list", TIERS, audit_k=200))
        r2 = A2.finalize("atk-inject")
        rb2 = B2.finalize("atk-inject")
        A2.confirm("atk-inject")
        B2.confirm("atk-inject")
        reps = {}
        for ch in ("random", "matched"):
            op = _write_opening(root / f"audit_cheat_{ch}.json", A2.audit_open("atk-inject", ch))
            reps[ch], _ = audit_verify(X2, "atk-inject", op, ch, evidence=root / "data/a.csv")
        docm = json.loads((root / "audit_cheat_matched.json").read_text("utf-8"))
        bad_pos = {(r["segment"], r["pos"]) for r in reps["matched"]["entries"] if r.get("genuine") is False}
        bad_people = {json.dumps(e["record"], sort_keys=True, ensure_ascii=False)
                      for e in docm["entries"] if (e["segment"], e["pos"]) in bad_pos}
        # 부정한 쪽이 매칭 감사 범위를 스스로 줄여 내는 경우
        lie = A2.audit_open("atk-inject", "custom", [[0, 0]])
        try:
            audit_verify(X2, "atk-inject", _write_opening(root / "audit_lie.json", lie), "matched")
            lie_caught = False
        except VerificationError:
            lie_caught = True
        n_el = sum(sg["count"] for sg in A2.own_msg("round1", "atk-inject").header["segments"])
        p_det = detection_probability(n_el, 2 * info["injected"], 200)
        log(f"  4-3 DP가 RKP 당원 {info['injected']}명을 자기 명부에 끼워 넣고 커밋 → 정밀 일치가 "
            f"{r2['persons']['strict']}명으로 부풀려짐 (RKP 쪽 결과에도 똑같이 {rb2['persons']['strict']}명으로 보임)")
        log(f"      무작위 감사 200건: 증빙 없음 {reps['random']['not_genuine']}건 적발 (이론 탐지확률 {p_det * 100:.1f}%)")
        log(f"      매칭 감사 {reps['matched']['opened']}건: 증빙 없음 {reps['matched']['not_genuine']}건"
            f"({len(bad_people)}명분) 적발 {'✓' if len(bad_people) == info['injected'] else '✗'}"
            f" · 감사 범위를 줄여 낸 응답은 {'거부 ✓' if lie_caught else '통과 ✗'} ({clock.lap()})")

        # ---------------- 4-4 중개인의 결과 위조
        _run(A, B, Hb, "atk-hub", make_params("list", TIERS))
        forge_hub_result(Hb, "atk-hub")
        rejected_by, accepted_by = [], []
        for P in (A, B):
            try:
                P.finalize("atk-hub")
                accepted_by.append(P.label)
            except VerificationError:
                rejected_by.append(P.label)
        confirm_blocked = True
        for label in accepted_by:
            try:
                (A if label == "DP" else B).confirm("atk-hub")
                confirm_blocked = False
            except VerificationError:
                pass
        caught_by = rejected_by if (rejected_by and confirm_blocked) else []
        log(f"  4-4 중개인이 매칭되지 않은 가짜 쌍 1개를 끼워 넣음 → {'·'.join(rejected_by) or '없음'}의 재확인에서 거부, "
            f"{'·'.join(accepted_by) or '없음'}는 confirm 에서 상대 거부를 확인하고 확정 중단 "
            f"{'✓' if caught_by else '✗'} ({clock.lap()})")

        allok = (ok1 and ok2 and okA and det1 and sealed_ok and hit == 0 and lie_caught
                 and len(bad_people) == info["injected"] and bool(caught_by))
        log("\n" + "=" * 66)
        log(f" 결과: {'전 과정 정상 ✓' if allok else '확인 필요 ✗'}"
            + (f"   작업 폴더(파일 확인용): {root}" if keep else "   (작업 폴더를 남기려면 --keep DIR)"))
        log("=" * 66)
        return {"all_ok": allok, "phase1_ok": ok1, "phase2_ok": ok2, "audits_ok": okA, "tamper_detected": det1,
                "probe_hits": hit, "sealed": sealed_ok, "inject_caught": len(bad_people), "lie_caught": lie_caught,
                "hub_forgery_caught_by": caught_by, "truth": truth, "dataset": info, "root": str(root)}
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)
