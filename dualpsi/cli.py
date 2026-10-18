"""명령줄 인터페이스.  python -m dualpsi <명령> --help"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .audit import audit_verify, verify_transcript, worklist_csv
from .messages import MessageError
from .normalize import TIER_KO
from .protocol import Hub, Party, ProtocolError, VerificationError, hub_init, make_params, setup
from .util import fingerprint, write_private_bytes, write_private_json


def _say(*a):
    print(*a, flush=True)


def _next(*lines):
    _say("\n다음 단계:")
    for l in lines:
        _say(f"  • {l}")


def _cols(a) -> dict:
    return {"name": a.col_name, "birth": a.col_birth, "phone": a.col_phone}


def _party(a) -> Party:
    return Party(a.work, a.exchange, a.workers, getattr(a, "roster", None))


# ---------------------------------------------------------------- 중개인

def cmd_hub_init(a):
    info = hub_init(a.work, a.exchange, a.label, a.name or "")
    _say(f"[{info['label']}] 중개인 초기화 완료")
    _say(f"  서명키 지문: {info['fingerprint']}   ← 양당과 전화나 서면으로 대조")
    _next(f"{Path(info['path']).name} 를 양당에 전달 (서명 공개키와 봉인용 공개키만 들어 있음)",
          "양당의 setup·round1·round2 메시지를 교환 폴더에 모은 뒤 mediate 실행")


def cmd_mediate(a):
    h = Hub(a.work, a.exchange, a.workers)
    t0 = time.time()
    r = h.mediate(a.session)
    _say(f"[{h.label}] 양측 2라운드 개봉·DLEQ 증명 검증 통과 ✓ ({time.time() - t0:.1f}초)")
    _say("  결과: " + ", ".join(f"{TIER_KO[c['tier']]} {c['matches']:,}건" for c in r["counts"])
         + (" (명단 모드: 매칭 위치 포함)" if r["mode"] == "list" else " (건수 모드: 건수만)"))
    _next(f"{r['send']} 를 양당에 같은 시각에 전달", "감사 응답(audit-open)을 받으면 audit-verify 로 검증")


# ---------------------------------------------------------------- 당사자

def cmd_setup(a):
    info = setup(a.work, a.exchange, a.label, a.roster, a.name or "", _cols(a), a.pivot_yy, a.max_records)
    _say(f"[{info['label']}] setup 완료")
    _say(f"  명부 {info['total_rows']:,}행 읽음 (인코딩 {info['encoding']}, 열 {info['columns']})")
    _say(f"  유효 {info['n_leaves']:,}명 · 제외 {info['rejects']}행 · 중복 병합 {info['duplicates']}행 · "
         f"전화번호 없음/인식불가 {info['phone_missing']}명(후보 등급으로만 비교)")
    if info["rejects"]:
        _say(f"  제외된 행 번호: {Path(a.work) / 'rejects.csv'}")
    _say(f"  명부 커밋(머클 루트): {info['root']}")
    _say(f"  서명키 지문: {info['fingerprint']}   ← 상대·중개인과 전화나 서면으로 대조")
    _next(f"{Path(info['setup_path']).name} 를 상대와 중개인에게 전달 (명부 내용은 들어 있지 않음)",
          "상대의 *.setup.msg 와 중개인의 *.hub.msg 를 교환 폴더에 넣고 round1 실행")


def cmd_round1(a):
    p = _party(a)
    tiers = [t.strip() for t in (a.tiers or ("strict,loose" if a.mode == "count" else "strict")).split(",") if t.strip()]
    params = make_params(a.mode, tiers, a.audit_k, a.purpose)
    if a.mode == "list" and "loose" in tiers:
        _say("⚠ 명단 모드에서 후보(loose) 등급을 쓰면, 우리 당원과 이름·생년월일이 같은 '상대 당의 다른 사람'"
             "(동명이인)이 상대 당원이라는 사실도 드러납니다. 법적 검토 후 사용하세요.")
    t0 = time.time()
    info = p.round1(a.session, params, a.peer_fingerprint, a.hub_fingerprint, a.peer_max_records)
    _say(f"[{p.label}] 세션 '{a.session}' 1라운드 완료 · {'명단' if a.mode == 'list' else '건수'} 모드 ({time.time() - t0:.1f}초)")
    _say(f"  상대: {info['peer']} {info['peer_display_name']} · 커밋 명부 {info['peer_n_leaves']:,}명 · 지문 {info['peer_fingerprint']}")
    _say(f"  중개인: {info['hub']} {info['hub_display_name']} · 지문 {info['hub_fingerprint']}")
    if not (a.peer_fingerprint and a.hub_fingerprint):
        _say("  ※ 사전에 받은 지문과 같은지 확인하세요 (--peer-fingerprint / --hub-fingerprint 로 강제 가능)")
    for sg in info["segments"]:
        _say(f"  보낸 원소[{TIER_KO[sg['tier']]}] {sg['count']:,}개")
    _next(f"{p.label}.{a.session}.round1.msg 를 상대와 중개인에게 전달",
          "상대의 round1 메시지를 교환 폴더에 넣고 round2 실행")


def cmd_round2(a):
    p = _party(a)
    t0 = time.time()
    out = p.round2(a.session)
    _say(f"[{p.label}] 2라운드 계산·봉인 완료 ({time.time() - t0:.1f}초)")
    _say(f"  {out['send']} 는 중개인({out['hub']})의 공개키로 봉인되어 중개인만 열 수 있습니다")
    _next(f"{out['send']} 를 중개인에게 전달", "중개인의 result 메시지를 받으면 finalize 실행")


def cmd_finalize(a):
    p = _party(a)
    t0 = time.time()
    try:
        res = p.finalize(a.session)
    except VerificationError:
        _say(f"[{p.label}] 중개인 결과를 거부했습니다. 거부 메시지 {p.label}.{a.session}.accept.msg 를 상대와 중개인에게 전달하세요")
        raise
    _say(f"[{p.label}] 중개인 결과 검증 통과 ✓ ({time.time() - t0:.1f}초) — 아직 확정 전입니다")
    if res["mode"] == "list":
        per = res["persons"]
        _say(f"  매칭 값 {len(res['pairs_own']):,}개를 우리 키로 재확인 ✓")
        _say(f"  이중당적 정밀 일치(이름·생년월일·전화): {per['strict']:,}명")
        if "loose" in res["tiers"]:
            _say(f"  후보(이름·생년월일만 일치 — 번호 변경 또는 동명이인, 본인 확인 필요): {per['candidate']:,}명")
        _say(f"  확정 전 명단: {p.sdir(a.session) / 'result.pending.csv'}  (우리 당원 정보만 들어 있음)")
    else:
        c = {x["tier"]: x["matches"] for x in res["counts"]}
        if "strict" in c:
            _say(f"  정밀 일치 건수: {c['strict']:,}")
        if "loose" in c:
            _say(f"  이름·생년월일 일치 건수: {c['loose']:,} (정밀 일치 포함, 동명이인이 섞일 수 있음)")
        _say("  ※ 건수 모드의 건수는 중개인 계산을 믿은 값입니다(양당이 다시 셀 수 없음). 2단계 결과와 대조하세요")
    _next(f"{p.label}.{a.session}.accept.msg(수락 서명) 를 상대와 중개인에게 전달",
          "상대의 accept 메시지를 받으면 confirm 으로 결과 확정")


def cmd_confirm(a):
    p = _party(a)
    r = p.confirm(a.session)
    _say(f"[{p.label}] 양당이 같은 결과를 검증·수락했습니다 — 결과 확정 ✓")
    if r["mode"] == "list":
        _say(f"  우리 측 해당자 명단: {p.sdir(a.session) / 'result.csv'}  (우리 당원 정보만 들어 있음)")
    for w in r.get("warnings") or []:
        _say(f"  ⚠ {w}")
    _next("audit-open 으로 감사 응답을 만들어 감사인에게만 전달", "감사가 끝나면 destroy-key 로 세션 키 폐기")


def cmd_audit_open(a):
    p = _party(a)
    positions = json.loads(Path(a.positions).read_text("utf-8")) if a.positions else None
    challenge = "custom" if positions is not None else a.challenge
    doc = p.audit_open(a.session, challenge, positions)
    write_private_json(Path(a.out), doc)
    _say(f"[{p.label}] 감사 응답 생성: {a.out} (공개 항목 {len(doc['entries'])}개, 종류 {challenge})")
    _say("  ※ 공개된 레코드가 들어 있습니다. 감사인에게만 전달하고 상대 당에는 보내지 마세요")


# ---------------------------------------------------------------- 감사인·참관인

def cmd_audit_verify(a):
    positions = json.loads(Path(a.positions).read_text("utf-8")) if a.positions else None
    rep, doc = audit_verify(a.exchange, a.session, a.opening, a.challenge, positions, a.evidence, _cols(a))
    _say(f"[감사] {rep['owner']} · 종류 {rep['challenge']} · 요구 {rep['expected_positions']}건 / 공개 {rep['opened']}건")
    _say(f"  위치 누락 {len(rep['missing'])} · 범위 밖 {len(rep['extra'])} · 중복 {'있음' if rep['duplicate_entries'] else '없음'}")
    _say(f"  암호 검증 실패 {rep['crypto_failures']}건 (머클 경로 + DLEQ)")
    if rep["genuineness"] == "evidence":
        _say(f"  증빙 대조: 증빙 없음 {rep['not_genuine']}건")
    else:
        _say(f"  실당원 확인 대기 {rep['pending_manual']}건 — --evidence 로 대조하거나 --worklist 로 목록을 뽑아 수작업 확인")
    if a.report:
        Path(a.report).write_text(json.dumps(rep, ensure_ascii=False, indent=2), "utf-8")
        _say(f"  보고서(레코드 미포함, 양측 공유 가능): {a.report}")
    if a.worklist:
        write_private_bytes(Path(a.worklist), worklist_csv(doc, rep))
        _say(f"  수작업 확인 목록(레코드 포함, 감사인 보관용): {a.worklist}")
    if rep["passed"]:
        _say("판정: 통과 ✓")
        return 0
    if rep["crypto_passed"] and rep["genuineness"] != "evidence":
        _say("판정: 암호 검증 통과 ✓ (실당원 확인은 별도)")
        return 0
    _say("판정: 부정 또는 오류 의심 ✗")
    return 3


def cmd_verify_transcript(a):
    V, issues = verify_transcript(a.exchange, a.session, a.hub_work, a.workers)
    _say(f"[전사본] 세션 '{V.session}' · {'명단' if V.params['mode'] == 'list' else '건수'} 모드 · sid {V.sid.hex()[:16]}…")
    for l in V.order:
        h = V.setups[l].header
        _say(f"  {l} {h.get('display_name', '')} · 명부 {h['n_leaves']:,}명 · 지문 {fingerprint(V.setups[l].pk)}")
    _say(f"  중개인 {V.hub.header['label']} {V.hub.header.get('display_name', '')} · 지문 {fingerprint(V.hub.pk)}")
    for l, acc in V.accepts.items():
        _say(f"  {l} 수락 상태: " + ("메시지 없음" if acc is None else
             ("수락" if acc.get("status") == "accepted" else f"거부 — {acc.get('reason')}")))
    if V.result is None:
        _say("  중개인 결과가 아직 없습니다 (1라운드까지 검증 통과)")
    else:
        _say("  배포된 결과: " + ", ".join(f"{TIER_KO[c['tier']]} {c['matches']:,}건" for c in V.result["counts"]))
        _say("  서명·세션 연결·감사 난수·결과 형식 검증 통과 ✓")
        if a.hub_work:
            _say("  봉인된 2라운드를 열어 DLEQ 증명과 결과를 재계산 → " + ("일치 ✓" if not issues else "불일치 ✗"))
    for issue in issues:
        _say(f"  ✗ {issue}")
    return 3 if issues else 0


def cmd_destroy_key(a):
    p = _party(a)
    p.destroy_key(a.session)
    _say(f"[{p.label}] 세션 '{a.session}' 의 PSI 키를 상태 파일에서 삭제했습니다 — 이후 감사 응답은 만들 수 없습니다")


def cmd_status(a):
    secret = json.loads((Path(a.work) / "secret.json").read_text("utf-8"))
    if secret.get("role") == "hub":
        h = Hub(a.work, a.exchange, a.workers)
        _say(f"[{h.label}] 중개인 {secret.get('display_name', '')} · 지문 {fingerprint(h.pk)}")
        for name, s in (secret.get("sessions") or {}).items():
            _say(f"  세션 {name}: {s['mode']} · 당사자 {', '.join(s['parties'])} · 결과 배포 {s['mediated_at']}")
        return
    p = _party(a)
    _say(f"[{p.label}] {p.secret.get('display_name', '')} · 명부 {p.secret['n_leaves']:,}명 · 지문 {fingerprint(p.pk)}")
    for name, s in (p.secret.get("sessions") or {}).items():
        _say(f"  세션 {name}: {s['params']['mode']} · 단계 {s['stage']} · 상대 {s['peer']} · 중개인 {s['hub']} · "
             f"키 {'보관' if 'psi_key' in s else '폐기됨'}")


def cmd_demo(a):
    from .demo import run_demo
    r = run_demo(a.size_a, a.size_b, a.dual, a.workers, a.keep)
    return 0 if r.get("all_ok") else 3


# ---------------------------------------------------------------- 파서

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="dualpsi", description="두 정당 명부를 서로 공개하지 않고 이중당적자를 산출합니다 "
                                 "(ECDH-PSI + DLEQ 영지식 증명 + 중립 중개인 + 명부 커밋·감사)")
    ap.add_argument("--version", action="version", version=f"dualpsi {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="명령")

    def actor_args(sp, session=True):
        sp.add_argument("--work", required=True, help="작업 폴더(비밀 상태 — 외부 반출 금지)")
        sp.add_argument("--exchange", required=True, help="교환 폴더(주고받는 공개 메시지)")
        if session:
            sp.add_argument("--session", default="main", help="세션 이름 (기본 main)")
        sp.add_argument("--workers", type=int, default=None, help="병렬 프로세스 수 (기본: CPU 수)")

    def col_args(sp):
        sp.add_argument("--col-name", help="이름 열 이름(자동 인식 실패 시)")
        sp.add_argument("--col-birth", help="생년월일 열 이름")
        sp.add_argument("--col-phone", help="휴대전화 열 이름")

    sp = sub.add_parser("hub-init", help="중개인: 서명키·봉인용 키 생성")
    actor_args(sp, session=False)
    sp.add_argument("--label", required=True, help="중개인 라벨(영문, 예: HUB)")
    sp.add_argument("--name", help="표시 이름(예: 중앙선거관리위원회)")
    sp.set_defaults(fn=cmd_hub_init)

    sp = sub.add_parser("setup", help="당사자: 명부 정규화·커밋, 서명키 생성")
    actor_args(sp, session=False)
    sp.add_argument("--label", required=True, help="당사자 라벨(영문, 예: DP, RKP)")
    sp.add_argument("--name", help="표시 이름(예: 더불어민주당)")
    sp.add_argument("--roster", required=True, help="명부 CSV (UTF-8 또는 CP949)")
    sp.add_argument("--pivot-yy", type=int, default=None, help="두 자리 연도 기준(이하면 2000년대). 양측 동일해야 함")
    sp.add_argument("--max-records", type=int, default=None, help="레코드 수 상한(초과 시 중단)")
    col_args(sp)
    sp.set_defaults(fn=cmd_setup)

    sp = sub.add_parser("round1", help="당사자: 우리 원소를 우리 키로 암호화해 상대·중개인에게 전송")
    actor_args(sp)
    sp.add_argument("--mode", choices=["list", "count"], default="list", help="list=명단(기본), count=건수만")
    sp.add_argument("--tiers", default=None,
                    help="매칭 등급 strict(정밀)·loose(후보). 기본: 건수 모드 strict,loose / 명단 모드 strict")
    sp.add_argument("--audit-k", type=int, default=200, help="무작위 감사 건수 (기본 200)")
    sp.add_argument("--purpose", default="", help="세션 목적 문구(양측 동일해야 함)")
    sp.add_argument("--peer-fingerprint", help="사전에 대조한 상대 지문(불일치 시 중단)")
    sp.add_argument("--hub-fingerprint", help="사전에 대조한 중개인 지문(불일치 시 중단)")
    sp.add_argument("--peer-max-records", type=int, help="상대 명부 크기 상한(공식 당원 수 등)")
    sp.add_argument("--roster", help="명부 파일 위치가 바뀐 경우 새 경로")
    sp.set_defaults(fn=cmd_round1)

    sp = sub.add_parser("round2", help="당사자: 상대 원소에 우리 키 적용 + DLEQ 증명, 중개인에게 봉인")
    actor_args(sp)
    sp.add_argument("--roster", help="명부 파일 위치가 바뀐 경우 새 경로")
    sp.set_defaults(fn=cmd_round2)

    sp = sub.add_parser("mediate", help="중개인: 양측 증명 검증, 매칭 계산, 서명 결과 배포")
    actor_args(sp)
    sp.set_defaults(fn=cmd_mediate)

    sp = sub.add_parser("finalize", help="당사자: 중개인 결과 검증 후 수락·거부 서명")
    actor_args(sp)
    sp.add_argument("--roster", help="명부 파일 위치가 바뀐 경우 새 경로")
    sp.set_defaults(fn=cmd_finalize)

    sp = sub.add_parser("confirm", help="당사자: 상대도 같은 결과를 수락했는지 확인하고 결과 확정")
    actor_args(sp)
    sp.set_defaults(fn=cmd_confirm)

    sp = sub.add_parser("audit-open", help="당사자: 감사 응답 생성(감사인 전용)")
    actor_args(sp)
    sp.add_argument("--challenge", choices=["random", "matched"], default="random",
                    help="random=감사 난수로 정한 무작위 위치, matched=매칭된 위치 전부")
    sp.add_argument("--positions", help="감사인이 지정한 위치 목록 JSON [[세그먼트, 위치], ...]")
    sp.add_argument("--out", required=True, help="감사 응답 파일(JSON)")
    sp.add_argument("--roster", help="명부 파일 위치가 바뀐 경우 새 경로")
    sp.set_defaults(fn=cmd_audit_open)

    sp = sub.add_parser("audit-verify", help="감사인: 감사 응답 검증(감사 범위는 감사인이 정함)")
    sp.add_argument("--exchange", required=True, help="setup·hub·round1·result 메시지가 있는 폴더")
    sp.add_argument("--session", default="main")
    sp.add_argument("--opening", required=True, help="당사자가 낸 감사 응답 JSON")
    sp.add_argument("--challenge", required=True, choices=["random", "matched", "custom"], help="요구한 감사 종류")
    sp.add_argument("--positions", help="custom 일 때 감사인이 정한 위치 목록 JSON")
    sp.add_argument("--evidence", help="실당원 증빙 CSV(입당원서·당비 기록 등에서 추출)")
    sp.add_argument("--report", help="보고서 저장 경로(레코드 미포함, 양측 공유 가능)")
    sp.add_argument("--worklist", help="수작업 확인 목록 CSV 저장 경로(레코드 포함)")
    col_args(sp)
    sp.set_defaults(fn=cmd_audit_verify)

    sp = sub.add_parser("verify-transcript", help="감사인·참관인: 공개 메시지로 전체 절차 재검증")
    sp.add_argument("--exchange", required=True)
    sp.add_argument("--session", default="main")
    sp.add_argument("--hub-work", help="중개인 작업 폴더(있으면 봉인된 2라운드까지 열어 결과를 재계산)")
    sp.add_argument("--workers", type=int, default=None)
    sp.set_defaults(fn=cmd_verify_transcript)

    sp = sub.add_parser("destroy-key", help="당사자: 세션 PSI 키 폐기")
    actor_args(sp)
    sp.set_defaults(fn=cmd_destroy_key)

    sp = sub.add_parser("status", help="작업 폴더 상태 보기")
    actor_args(sp, session=False)
    sp.set_defaults(fn=cmd_status)

    sp = sub.add_parser("demo", help="가상 명부로 전체 절차와 공격 탐지 시연")
    sp.add_argument("--size-a", type=int, default=12000)
    sp.add_argument("--size-b", type=int, default=5000)
    sp.add_argument("--dual", type=int, default=300)
    sp.add_argument("--workers", type=int, default=None)
    sp.add_argument("--keep", help="작업 폴더를 지우지 않고 남길 경로")
    sp.set_defaults(fn=cmd_demo)
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    try:
        return a.fn(a) or 0
    except VerificationError as e:
        _say(f"\n검증 실패 ✗: {e}")
        return 3
    except (ProtocolError, MessageError, ValueError, FileNotFoundError) as e:
        _say(f"\n오류: {e}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
