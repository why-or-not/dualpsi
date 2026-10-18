"""CLI 종단간: 세 참여자가 각자 교환 폴더를 갖고 파일을 복사해 주고받는 실제 운영 형태를 재현."""

import shutil
import subprocess
import sys
from pathlib import Path

from dualpsi.demo import make_dataset

ROOT = Path(__file__).resolve().parents[1]


def run(*args, ok=(0,)):
    r = subprocess.run([sys.executable, "-m", "dualpsi", *map(str, args)], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode in ok, r.stdout + r.stderr
    return r.stdout


def send(src: Path, pattern: str, *dsts: Path):
    files = list(src.glob(pattern))
    assert files, pattern
    for p in files:
        for d in dsts:
            shutil.copy(p, d / p.name)


def fp(out: str, label: str) -> str:
    return " ".join(out.split(label)[1].split()[:6])


def _prepare(tmp_path, na=300, nb=150, nd=30):
    make_dataset(tmp_path / "data", na, nb, nd)
    xa, xb, xh = (tmp_path / n for n in ("xa", "xb", "xh"))
    for d in (xa, xb, xh):
        d.mkdir()
    fh = fp(run("hub-init", "--work", tmp_path / "wh", "--exchange", xh, "--label", "HUB", "--name", "중개"), "지문: ")
    fa = fp(run("setup", "--work", tmp_path / "wa", "--exchange", xa, "--label", "DP", "--roster",
                tmp_path / "data/a.csv", "--pivot-yy", 10), "지문: ")
    fb = fp(run("setup", "--work", tmp_path / "wb", "--exchange", xb, "--label", "RKP", "--roster",
                tmp_path / "data/b.csv", "--pivot-yy", 10), "지문: ")
    send(xh, "HUB.hub.msg", xa, xb)
    send(xa, "DP.setup.msg", xb, xh)
    send(xb, "RKP.setup.msg", xa, xh)
    return xa, xb, xh, fa, fb, fh


def test_cli_list_flow(tmp_path):
    xa, xb, xh, fa, fb, fh = _prepare(tmp_path)
    s = ["--session", "s1", "--workers", "1"]
    run("round1", "--work", tmp_path / "wa", "--exchange", xa, *s, "--audit-k", 10,
        "--peer-fingerprint", fb, "--hub-fingerprint", fh)
    run("round1", "--work", tmp_path / "wb", "--exchange", xb, *s, "--audit-k", 10,
        "--peer-fingerprint", fa, "--hub-fingerprint", fh)
    send(xa, "DP.s1.round1.msg", xb, xh)
    send(xb, "RKP.s1.round1.msg", xa, xh)
    run("round2", "--work", tmp_path / "wa", "--exchange", xa, *s)
    run("round2", "--work", tmp_path / "wb", "--exchange", xb, *s)
    send(xa, "DP.s1.round2.msg", xh)  # 2라운드는 중개인에게만
    send(xb, "RKP.s1.round2.msg", xh)
    assert "검증 통과" in run("mediate", "--work", tmp_path / "wh", "--exchange", xh, *s)
    send(xh, "HUB.s1.result.msg", xa, xb)
    out_a = run("finalize", "--work", tmp_path / "wa", "--exchange", xa, *s)
    run("finalize", "--work", tmp_path / "wb", "--exchange", xb, *s)
    assert "재확인 ✓" in out_a and not (tmp_path / "wa/sessions/s1/result.csv").exists()  # 확정 전
    send(xa, "DP.s1.accept.msg", xb, xh)
    send(xb, "RKP.s1.accept.msg", xa, xh)
    assert "결과 확정 ✓" in run("confirm", "--work", tmp_path / "wa", "--exchange", xa, *s)
    run("confirm", "--work", tmp_path / "wb", "--exchange", xb, *s)
    assert (tmp_path / "wa/sessions/s1/result.csv").exists()
    out = run("verify-transcript", "--exchange", xh, "--session", "s1", "--hub-work", tmp_path / "wh", "--workers", "1")
    assert "일치 ✓" in out
    run("audit-open", "--work", tmp_path / "wa", "--exchange", xa, *s, "--challenge", "matched", "--out", tmp_path / "o.json")
    out = run("audit-verify", "--exchange", xh, "--session", "s1", "--opening", tmp_path / "o.json", "--challenge", "matched",
              "--evidence", tmp_path / "data/a.csv", "--report", tmp_path / "rep.json", "--worklist", tmp_path / "wl.csv")
    assert "판정: 통과" in out
    assert "record" not in (tmp_path / "rep.json").read_text("utf-8")  # 보고서에는 레코드가 없다
    # 감사 종류를 다르게 요구하면 거부
    assert "검증 실패" in run("audit-verify", "--exchange", xh, "--session", "s1", "--opening", tmp_path / "o.json",
                              "--challenge", "random", ok=(3,))
    run("destroy-key", "--work", tmp_path / "wa", "--exchange", xa, "--session", "s1")
    assert "폐기됨" in run("status", "--work", tmp_path / "wa", "--exchange", xa)
    assert "결과 배포" in run("status", "--work", tmp_path / "wh", "--exchange", xh)


def test_cli_count_flow_and_wrong_fingerprint(tmp_path):
    xa, xb, xh, fa, fb, fh = _prepare(tmp_path, 200, 100, 20)
    s = ["--session", "c", "--workers", "1"]
    assert "검증 실패" in run("round1", "--work", tmp_path / "wa", "--exchange", xa, *s, "--mode", "count",
                              "--hub-fingerprint", "0000 0000 0000 0000 0000 0000", ok=(3,))
    for w, x in (("wa", xa), ("wb", xb)):
        run("round1", "--work", tmp_path / w, "--exchange", x, *s, "--mode", "count")
    send(xa, "DP.c.round1.msg", xb, xh)
    send(xb, "RKP.c.round1.msg", xa, xh)
    for w, x in (("wa", xa), ("wb", xb)):
        run("round2", "--work", tmp_path / w, "--exchange", x, *s)
    send(xa, "DP.c.round2.msg", xh)
    send(xb, "RKP.c.round2.msg", xh)
    run("mediate", "--work", tmp_path / "wh", "--exchange", xh, *s)
    send(xh, "HUB.c.result.msg", xa, xb)
    out = run("finalize", "--work", tmp_path / "wa", "--exchange", xa, *s)
    assert "정밀 일치 건수" in out and "이름·생년월일 일치 건수" in out and "중개인 계산을 믿은 값" in out
    run("finalize", "--work", tmp_path / "wb", "--exchange", xb, *s)
    send(xb, "RKP.c.accept.msg", xa)
    assert "결과 확정 ✓" in run("confirm", "--work", tmp_path / "wa", "--exchange", xa, *s)
