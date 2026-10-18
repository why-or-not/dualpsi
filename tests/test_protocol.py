import json

import pytest
from nacl.public import PrivateKey

from dualpsi.audit import audit_verify, verify_transcript
from dualpsi.demo import _resign, forge_hub_result, forge_round2, make_dataset, plaintext_truth, plant_probes
from dualpsi.group import mul_base
from dualpsi.messages import MessageError, read_msg, sign_json
from dualpsi.normalize import TIERS, load_roster
from dualpsi.protocol import (Hub, Party, ProtocolError, VerificationError, hub_init, make_params, open_round2,
                              setup)

PIVOT = 10


@pytest.fixture
def world(tmp_path):
    info = make_dataset(tmp_path / "data", 400, 200, 40)
    X = tmp_path / "x"
    hub_init(tmp_path / "H", X, "HUB", "중개")
    setup(tmp_path / "A", X, "DP", tmp_path / "data/a.csv", "가당", pivot_yy=PIVOT)
    setup(tmp_path / "B", X, "RKP", tmp_path / "data/b.csv", "나당", pivot_yy=PIVOT)
    return {"tmp": tmp_path, "X": X, "A": Party(tmp_path / "A", X, 1), "B": Party(tmp_path / "B", X, 1),
            "H": Hub(tmp_path / "H", X, 1), "info": info,
            "truth": plaintext_truth(tmp_path / "data/a.csv", tmp_path / "data/b.csv", PIVOT)}


def _run(w, session, params, after_round1=None, after_round2=None):
    A, B, H = w["A"], w["B"], w["H"]
    A.round1(session, params)
    B.round1(session, params)
    if after_round1:
        after_round1()
    A.round2(session)
    B.round2(session)
    if after_round2:
        after_round2()
    H.mediate(session)


def _finish(w, session):
    ra, rb = w["A"].finalize(session), w["B"].finalize(session)
    w["A"].confirm(session)
    w["B"].confirm(session)
    return ra, rb


def _open(w, name, doc):
    p = w["tmp"] / name
    p.write_text(json.dumps(doc, ensure_ascii=False), "utf-8")
    return p


def test_list_mode_matches_plaintext(world):
    _run(world, "s", make_params("list", TIERS, audit_k=20))
    ra, rb = _finish(world, "s")
    t = world["truth"]
    assert ra["persons"] == t["persons"]
    assert [c["matches"] for c in ra["counts"]] == [t["strict"], t["loose"]] == [c["matches"] for c in rb["counts"]]
    assert len(ra["pairs_own"]) == len(rb["pairs_own"]) == t["strict"] + t["loose"]
    V, issues = verify_transcript(world["X"], "s", world["tmp"] / "H", 1)
    assert issues == [] and V.result is not None
    csvtext = (world["A"].sdir("s") / "result.csv").read_text("utf-8-sig")
    assert csvtext.count("\n정밀,") == t["persons"]["strict"]


def test_count_mode_gives_counts_only(world):
    _run(world, "c", make_params("count", TIERS))
    ra = world["A"].finalize("c")
    t = world["truth"]
    assert [c["matches"] for c in ra["counts"]] == [t["strict"], t["loose"]]
    assert "pairs_own" not in ra
    assert read_msg(world["X"] / "HUB.c.result.msg").payload == b""


def test_round2_is_sealed_to_hub(world):
    _run(world, "z", make_params())
    r2 = read_msg(world["X"] / "DP.z.round2.msg")
    with pytest.raises(VerificationError):
        open_round2(r2, PrivateKey.generate())  # 상대 당(또는 누구든)은 열 수 없다
    assert open_round2(r2, world["H"].enc_sk)[4]  # 중개인만 연다


def test_round2_tamper_detected_by_hub(world):
    def evil(pts):
        pts[-1] = mul_base((5).to_bytes(32, "little"))

    with pytest.raises(VerificationError, match="DLEQ"):
        _run(world, "t", make_params("list", TIERS), after_round2=lambda: forge_round2(world["B"], "t", evil))


def test_probes_learn_nothing_and_fail_audit(world):
    """검토에서 지적된 떠보기 공격: 키를 쓰지 않은 원소를 섞어 상대 명부를 조회하려는 시도."""
    a_keys = sorted(r.key("strict") for r in load_roster(world["tmp"] / "data/a.csv", PIVOT).records if r.key("strict"))
    targets = a_keys[:6] + [f"가짜{i}|19700101|0101234{i:04d}" for i in range(6)]
    slots = []
    _run(world, "p", make_params("list", TIERS, audit_k=20),
         after_round1=lambda: slots.extend(plant_probes(world["B"], "p", targets)))
    _, rb = _finish(world, "p")
    assert not any(sg == 0 and op in slots for sg, op, _ in rb["pairs_own"])  # 떠보기는 아무 결과도 만들지 않는다
    pos = [[0, s] for s in slots]
    rep, _ = audit_verify(world["X"], "p", _open(world, "probe.json", world["B"].audit_open("p", "custom", pos)),
                          "custom", pos)
    assert rep["crypto_failures"] == len(slots) and not rep["crypto_passed"]  # 감사에 걸리면 드러난다


def test_hub_forgery_blocked_by_mutual_acceptance(world):
    """중개인이 한쪽 재확인만 통과하는 가짜 쌍을 넣는 경우(2차 검토 지적): 한쪽은 거부, 다른 쪽은 확정 불가."""
    _run(world, "f", make_params("list", TIERS))
    forge_hub_result(world["H"], "f")
    accepted, rejected = [], []
    for P in (world["A"], world["B"]):
        try:
            P.finalize("f")
            accepted.append(P)
        except VerificationError:
            rejected.append(P)
    assert len(rejected) >= 1
    for P in accepted:
        with pytest.raises(VerificationError, match="거부"):
            P.confirm("f")
        assert not (P.sdir("f") / "result.csv").exists()  # 확정 명단은 만들어지지 않는다
    for P in rejected:
        with pytest.raises(ProtocolError):
            P.confirm("f")
    _, issues = verify_transcript(world["X"], "f")
    assert any("거부" in i for i in issues)


def test_result_for_other_round2_rejected(world):
    _run(world, "r", make_params())
    rp = world["X"] / "HUB.r.result.msg"
    h = read_msg(rp).header
    _resign(rp, world["H"].sk, update={"round2_ids": [h["round2_ids"][1], h["round2_ids"][0]]})
    with pytest.raises(VerificationError, match="2라운드"):
        world["A"].finalize("r")


def test_count_inflation_flagged_across_sessions(world):
    """건수 모드 건수는 양당이 다시 셀 수 없다. 대신 같은 명부로 한 명단 세션과 대조해 드러낸다."""
    _run(world, "c1", make_params("count", ("strict",)))
    rp = world["X"] / "HUB.c1.result.msg"
    counts = read_msg(rp).header["counts"]
    counts[0]["matches"] += 5
    _resign(rp, world["H"].sk, update={"counts": counts})
    _finish(world, "c1")  # 부풀린 건수도 형식상 통과
    _run(world, "l1", make_params("list", ("strict",)))
    world["A"].finalize("l1")
    world["B"].finalize("l1")
    r = world["A"].confirm("l1")
    assert r["warnings"] and "c1" in r["warnings"][0]


def test_result_signed_by_other_key_rejected(world):
    _run(world, "k", make_params())
    _resign(world["X"] / "HUB.k.result.msg", world["A"].sk)
    with pytest.raises(MessageError):
        world["A"].finalize("k")


def test_param_mismatch(world):
    world["A"].round1("m", make_params("list", TIERS, audit_k=10))
    world["B"].round1("m", make_params("list", TIERS, audit_k=11))
    with pytest.raises(VerificationError):
        world["A"].round2("m")


def test_roster_change_rejected(world):
    roster = world["tmp"] / "data/a.csv"
    roster.write_bytes(roster.read_bytes() + "추가,1999-01-01,010-0000-0000\n".encode("utf-8"))
    with pytest.raises(ProtocolError, match="해시"):
        world["A"].round1("z", make_params())


def test_fingerprints_enforced(world):
    with pytest.raises(VerificationError, match="상대"):
        world["A"].round1("f1", make_params(), peer_fingerprint="0000 0000 0000 0000 0000 0000")
    with pytest.raises(VerificationError, match="중개인"):
        world["A"].round1("f2", make_params(), hub_fingerprint="0000 0000 0000 0000 0000 0000")


def test_audits_honest_and_forged(world):
    A = world["A"]
    _run(world, "a", make_params("list", TIERS, audit_k=25))
    world["A"].finalize("a")
    with pytest.raises(ProtocolError, match="수락"):  # 감사인은 양당 수락 메시지가 모두 있어야 진행
        audit_verify(world["X"], "a", _open(world, "early.json", {"label": "DP"}), "random")
    with pytest.raises(ProtocolError, match="confirm"):
        A.audit_open("a", "random")  # 상호 수락 확인 전에는 감사 응답을 만들지 않는다
    world["B"].finalize("a")
    A.confirm("a")
    world["B"].confirm("a")
    for ch in ("random", "matched"):
        rep, _ = audit_verify(world["X"], "a", _open(world, f"{ch}.json", A.audit_open("a", ch)), ch,
                              evidence=world["tmp"] / "data/a.csv")
        assert rep["passed"] and rep["opened"] == rep["expected_positions"]
    # 응답자가 감사 종류를 바꿔 적으면 거부, custom 은 감사인이 위치를 줘야만 가능
    with pytest.raises(VerificationError, match="감사 종류"):
        audit_verify(world["X"], "a", _open(world, "lie.json", A.audit_open("a", "custom", [[0, 0]])), "matched")
    with pytest.raises(ProtocolError):
        audit_verify(world["X"], "a", world["tmp"] / "lie.json", "custom")
    # 레코드를 바꿔치기한 응답 → 머클 경로 불일치
    doc = A.audit_open("a", "random")
    doc["entries"][0]["record"]["name"] = "가짜이름"
    doc = sign_json({k: v for k, v in doc.items() if k != "sig"}, A.sk)
    rep, _ = audit_verify(world["X"], "a", _open(world, "forged.json", doc), "random")
    assert rep["crypto_failures"] == 1 and not rep["crypto_passed"]
    # 위치를 빼먹은 응답 / 빈 응답
    for name, cut in (("partial", 1), ("empty", None)):
        doc = A.audit_open("a", "matched")
        doc["entries"] = doc["entries"][cut:] if cut else []
        doc = sign_json({k: v for k, v in doc.items() if k != "sig"}, A.sk)
        rep, _ = audit_verify(world["X"], "a", _open(world, f"{name}.json", doc), "matched")
        assert not rep["crypto_passed"] and len(rep["missing"]) == (1 if cut else rep["expected_positions"])


def test_injection_caught_by_matched_audit(world):
    tmp, info = world["tmp"], world["info"]
    X2 = tmp / "x2"
    X2.mkdir()
    for n in ("RKP.setup.msg", "HUB.hub.msg"):
        (X2 / n).write_bytes((world["X"] / n).read_bytes())
    setup(tmp / "A2", X2, "DP", tmp / "data/a_injected.csv", pivot_yy=PIVOT)
    w2 = {"A": Party(tmp / "A2", X2, 1), "B": Party(tmp / "B", X2, 1), "H": Hub(tmp / "H", X2, 1)}
    _run(w2, "i", make_params("list", TIERS, audit_k=25))
    r, rb = _finish(w2, "i")
    assert r["persons"]["strict"] == world["truth"]["persons"]["strict"] + info["injected"]
    assert len(rb["pairs_own"]) == len(r["pairs_own"])  # 끼워 넣은 매칭은 상대에게도 똑같이 보인다
    rep, _ = audit_verify(X2, "i", _open(world, "m.json", w2["A"].audit_open("i", "matched")), "matched",
                          evidence=tmp / "data/a.csv")
    assert rep["crypto_passed"] and not rep["passed"]
    assert rep["not_genuine"] == 2 * info["injected"]  # 1명당 정밀·후보 원소 2개


def test_key_and_session_hygiene(world):
    A = world["A"]
    _run(world, "d", make_params())
    with pytest.raises(ProtocolError, match="이미"):
        A.round1("d", make_params())  # 같은 세션 재시작 불가
    with pytest.raises(ProtocolError, match="이미"):
        A.round2("d")  # 같은 키로 2라운드 재계산 불가
    with pytest.raises(ProtocolError, match="이미"):
        world["H"].mediate("d")
    A.finalize("d")
    A.destroy_key("d")
    with pytest.raises(ProtocolError, match="폐기"):
        A.audit_open("d", "random")
