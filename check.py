#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check.py - 리눅스 서버 읽기 전용 보안 점검
           계정 7 · 서비스 5 · 파일 시스템 6 = 18개 항목
제작: 너구리 (ㄴㄱㄹ)

사용법
  python3 check.py                       # 점검 후 report.html 생성
  sudo python3 check.py                  # /etc/shadow 등 root 전용 파일까지 점검
  python3 check.py --asset-id SRV-001 --grade "2등급(중)" --out report.html --json result.json

읽기 전용 원칙
  - 설정 파일은 open(path, "r") 로만 읽고, 권한·소유자는 os.stat() 으로만 확인한다.
  - 외부 명령을 실행하지 않는다. 열린 포트는 /proc/net/{tcp,tcp6,udp,udp6} 을 읽어 판단한다.
  - 디스크에 쓰는 파일은 결과서(--out, --json) 뿐이다.
"""
import argparse
import datetime
import glob
import grp
import html
import json
import os
import platform
import pwd
import re
import socket
import stat
import sys
from string import Template

VERSION = "1.0"
GOOD, BAD, NA, ERR = "양호", "취약", "해당 없음", "점검 불가"
CATS = ["계정 관리", "서비스 관리", "파일 시스템"]


# ───────────────────────── 읽기 도우미 ─────────────────────────
class Unreadable(Exception):
    def __init__(self, path, why):
        self.path, self.why = path, why
        super().__init__("%s: %s" % (path, why))


_cache = {}


def lines_of(path):
    """[(줄번호, 원문)] 반환. 파일이 없으면 None, 권한이 없으면 Unreadable."""
    if path in _cache:
        return _cache[path]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            res = [(i, l.rstrip("\n")) for i, l in enumerate(f, 1)]
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        res = None
    except PermissionError:
        raise Unreadable(path, "읽기 권한 없음")
    _cache[path] = res
    return res


def active(lines):
    """주석과 빈 줄을 뺀 (줄번호, 원문, 정리된 문자열)"""
    for no, raw in lines or []:
        s = raw.strip()
        if s and not s.startswith("#"):
            yield no, raw, s


def kv_find(path, key):
    """'key value' 와 'key = value' 형식을 모두 찾는다. [(줄번호, 원문, 값)]"""
    pat = re.compile(r"^" + re.escape(key) + r"(?:\s*=\s*|\s+)(\S.*?)\s*$", re.I)
    out = []
    for no, raw, s in active(lines_of(path)):
        m = pat.match(s)
        if m:
            out.append((no, raw, m.group(1).split("#")[0].strip()))
    return out


def to_int(v, base=10):
    try:
        return int(v, base)
    except (TypeError, ValueError):
        return None


def ev(path, line=None, text=""):
    return {"file": path, "line": line, "text": (text or "").rstrip("\n")}


def stat_text(path):
    st = os.stat(path)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    mode = stat.S_IMODE(st.st_mode)
    return st, mode, "stat() → 소유자 %s:%s, 권한 %04o (%s)" % (owner, group, mode, stat.filemode(st.st_mode))


# ───────────────────────── sshd 설정 (Include·Match 반영) ─────────────────────────
SSHD = "/etc/ssh/sshd_config"


def sshd_effective():
    seq = []

    def walk(path, depth):
        if depth > 5:
            return
        ls = lines_of(path)
        if ls is None:
            return
        in_match = False
        for no, raw, s in active(ls):
            parts = s.split(None, 1)
            k = parts[0].lower()
            v = parts[1].strip() if len(parts) > 1 else ""
            if k == "match":
                in_match = True
                continue
            if in_match:
                continue
            if k == "include":
                for pat in v.split():
                    if not pat.startswith("/"):
                        pat = os.path.join("/etc/ssh", pat)
                    for p in sorted(glob.glob(pat)):
                        walk(p, depth + 1)
                continue
            seq.append((path, no, raw, k, v))

    walk(SSHD, 0)
    return seq


def sshd_get(key):
    """sshd 는 처음 나온 값을 쓴다. (파일, 줄, 원문, 값) 또는 None"""
    for path, no, raw, k, v in sshd_effective():
        if k == key.lower():
            return path, no, raw, (v.split()[0] if v else "")
    return None


# ───────────────────────── 열린 포트 (/proc/net) ─────────────────────────
def _addr(hexaddr):
    ip, port = hexaddr.split(":")
    if len(ip) == 8:
        ip = ".".join(str(int(ip[i:i + 2], 16)) for i in (6, 4, 2, 0))
    else:
        ip = "[v6]"
    return ip, int(port, 16)


_listen = None


def listening():
    global _listen
    if _listen is not None:
        return _listen
    res = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        path = "/proc/net/" + name
        for no, raw in (lines_of(path) or [])[1:]:
            p = raw.split()
            if len(p) < 4:
                continue
            if (proto == "tcp" and p[3] == "0A") or (proto == "udp" and p[3] == "07"):
                ip, port = _addr(p[1])
                res.append({"proto": proto, "port": port, "ip": ip, "file": path, "line": no,
                            "text": "%s  %s  st=%s  (%s:%d)" % (p[0], p[1], p[3], ip, port)})
    _listen = res
    return res


def port_summary(proto):
    ports = sorted({l["port"] for l in listening() if l["proto"] == proto})
    files = "/proc/net/tcp, tcp6" if proto == "tcp" else "/proc/net/udp, udp6"
    state = "LISTEN" if proto == "tcp" else "수신 대기"
    return ev(files, None, "%s %s 포트: %s" % (proto.upper(), state, ", ".join(map(str, ports)) or "없음"))


def port_hits(proto, ports):
    return [l for l in listening() if l["proto"] == proto and l["port"] in ports]


def inetd_hits(names):
    out = []
    for p in ["/etc/inetd.conf"] + sorted(glob.glob("/etc/xinetd.d/*")):
        for no, raw, s in active(lines_of(p)):
            base = os.path.basename(p)
            if p == "/etc/inetd.conf":
                if s.split()[0] in names:
                    out.append(ev(p, no, raw))
            elif base in names and re.match(r"disable\s*=\s*no", s, re.I):
                out.append(ev(p, no, raw))
    return out


# ───────────────────────── PAM ─────────────────────────
def pam_files(kind):
    deb = {"auth": ["/etc/pam.d/common-auth"], "password": ["/etc/pam.d/common-password"]}
    rh = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    return [p for p in deb[kind] + rh if os.path.exists(p)]


def pam_hits(files, module, typ):
    out = []
    for p in files:
        for no, raw, s in active(lines_of(p)):
            if s.split()[0].lstrip("-") == typ and module in s:
                out.append((p, no, raw, s))
    return out


def pam_stack(files, typ, limit=4):
    return [ev(p, no, raw) for p in files for no, raw, s in active(lines_of(p))
            if s.split()[0].lstrip("-") == typ][:limit]


# ───────────────────────── 점검 항목 ─────────────────────────
CHECKS = []


def check(cid, cat, title, ref, prio, crit, fix):
    def deco(fn):
        CHECKS.append(dict(id=cid, cat=cat, title=title, ref=ref, prio=prio, crit=crit, fix=fix, fn=fn))
        return fn
    return deco


# ── 계정 관리 ──
@check("A-01", "계정 관리", "root 계정 원격 접속 제한", "U-01", "상",
       "SSH PermitRootLogin no (원격 터미널 서비스 미사용 시 양호)",
       "sshd_config.d/50-hardening.conf 에 PermitRootLogin no → sshd -t → systemctl reload ssh")
def a01():
    if lines_of(SSHD) is None:
        p22 = port_hits("tcp", {22})
        if not p22:
            return GOOD, "SSH 서버 미설치, 22/tcp 미사용", [ev(SSHD, None, "파일 없음"), port_summary("tcp")]
        h = p22[0]
        return BAD, "sshd_config 없이 22/tcp 가 열려 있음", [ev(h["file"], h["line"], h["text"])]
    r = sshd_get("PermitRootLogin")
    if r is None:
        return BAD, "PermitRootLogin 미설정 → 기본값 prohibit-password (키 인증 root 로그인 허용)", \
            [ev(SSHD, None, "PermitRootLogin 지시어 없음 (Include 된 sshd_config.d/*.conf 포함 검색)")]
    path, no, raw, v = r
    if v.lower() == "no":
        return GOOD, "root 원격 로그인 차단", [ev(path, no, raw)]
    return BAD, "PermitRootLogin %s → root 원격 로그인 가능" % v, [ev(path, no, raw)]


@check("A-02", "계정 관리", "비밀번호 복잡성 설정", "U-02", "상",
       "2종 이상 조합 10자 이상 또는 3종 이상 조합 8자 이상, PAM password 스택에 pam_pwquality 적용",
       "apt install libpam-pwquality → pwquality.conf 에 minlen=8, minclass=3, enforce_for_root")
def a02():
    files = pam_files("password")
    hits = pam_hits(files, "pam_pwquality.so", "password") + pam_hits(files, "pam_cracklib.so", "password")
    if not hits:
        evs = pam_stack(files, "password") or [ev("/etc/pam.d", None, "PAM password 스택 파일 없음")]
        return BAD, "password 스택에 pam_pwquality(pam_cracklib) 없음 → 복잡성 검사 미적용", evs
    p, no, raw, s = hits[0]
    evs = [ev(p, no, raw)]
    conf = "/etc/security/pwquality.conf"
    vals = {"minlen": 8, "minclass": 0, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0}
    found = False
    for k in vals:
        f = kv_find(conf, k)
        if f and to_int(f[-1][2]) is not None:
            vals[k] = to_int(f[-1][2])
            evs.append(ev(conf, f[-1][0], f[-1][1]))
            found = True
    for m in re.finditer(r"\b(minlen|minclass|[dulo]credit)=(-?\d+)", s):
        vals[m.group(1)] = int(m.group(2))
        found = True
    if not found:
        evs.append(ev(conf, None, "minlen·minclass 설정 없음 → 기본값 minlen=8, minclass=0"))
    neg = sum(1 for k in ("dcredit", "ucredit", "lcredit", "ocredit") if vals[k] < 0)
    classes = max(vals["minclass"], neg)
    ok = (classes >= 3 and vals["minlen"] >= 8) or (classes >= 2 and vals["minlen"] >= 10)
    reason = "minlen=%d, 필수 문자 종류 %d종" % (vals["minlen"], classes)
    return (GOOD, reason, evs) if ok else (BAD, reason + " → 기준 미달", evs)


@check("A-03", "계정 관리", "계정 잠금 임계값 설정", "U-03", "상",
       "로그인 실패 잠금 임계값 10회 이하 (auth 스택에 pam_faillock 적용)",
       "common-auth 에 pam_faillock preauth/authfail 추가, faillock.conf deny=5 unlock_time=900")
def a03():
    files = pam_files("auth")
    hits = pam_hits(files, "pam_faillock.so", "auth") + pam_hits(files, "pam_tally2.so", "auth")
    conf = "/etc/security/faillock.conf"
    cd = kv_find(conf, "deny")
    if not hits:
        evs = pam_stack(files, "auth")
        if cd:
            evs.append(ev(conf, cd[-1][0], cd[-1][1]))
        note = " (faillock.conf 에 값은 있으나 PAM 에서 모듈을 부르지 않음)" if cd else ""
        return BAD, "auth 스택에 pam_faillock 없음 → 로그인 실패 잠금 미적용" + note, evs
    evs = [ev(p, no, raw) for p, no, raw, s in hits]
    deny = None
    for p, no, raw, s in hits:
        m = re.search(r"\bdeny=(\d+)", s)
        if m:
            deny = int(m.group(1))
    if deny is None and cd and to_int(cd[-1][2]) is not None:
        deny = to_int(cd[-1][2])
        evs.append(ev(conf, cd[-1][0], cd[-1][1]))
    if deny is None:
        deny = 3
        evs.append(ev(conf, None, "deny 미설정 → pam_faillock 기본값 3"))
    if 0 < deny <= 10:
        return GOOD, "deny=%d (10회 이하)" % deny, evs
    return BAD, "deny=%d → 기준(10회 이하) 초과 또는 비활성" % deny, evs


@check("A-04", "계정 관리", "비밀번호 파일 보호 (shadow 사용)", "U-04", "상",
       "/etc/passwd 두 번째 필드가 모두 x 이고 /etc/shadow 를 사용",
       "pwconv 로 shadow 전환, /etc/passwd 의 해시 제거")
def a04():
    rows = list(active(lines_of("/etc/passwd")))
    bad = []
    for no, raw, s in rows:
        f = s.split(":")
        if len(f) > 1 and f[1] != "x":
            masked = ":".join([f[0], "<해시 가림>" if f[1] else "<빈 값>"] + f[2:])
            bad.append(ev("/etc/passwd", no, masked))
    if bad:
        return BAD, "두 번째 필드가 x 가 아닌 계정 %d개" % len(bad), bad[:5]
    if not os.path.exists("/etc/shadow"):
        return BAD, "/etc/shadow 없음", [ev("/etc/shadow", None, "파일 없음")]
    return GOOD, "계정 %d개 모두 shadow 사용" % len(rows), \
        [ev("/etc/passwd", "1–%d" % rows[-1][0], "전체 %d개 줄의 2번째 필드 = x" % len(rows)),
         ev("/etc/shadow", None, stat_text("/etc/shadow")[2])]


@check("A-05", "계정 관리", "root 이외 UID 0 금지", "U-44", "중",
       "root 외에 UID 가 0 인 계정이 없음",
       "usermod -u <새 UID> <계정> 또는 userdel <계정>")
def a05():
    hits, root = [], None
    for no, raw, s in active(lines_of("/etc/passwd")):
        f = s.split(":")
        if len(f) > 2 and f[2] == "0":
            if f[0] == "root":
                root = ev("/etc/passwd", no, raw)
            else:
                hits.append(ev("/etc/passwd", no, raw))
    if hits:
        return BAD, "UID 0 계정 %d개: %s" % (len(hits), ", ".join(h["text"].split(":")[0] for h in hits)), hits
    return GOOD, "UID 0 은 root 하나뿐", [root] if root else []


@check("A-06", "계정 관리", "비밀번호 최대 사용기간", "U-47", "중",
       "PASS_MAX_DAYS 90 이하",
       "login.defs PASS_MAX_DAYS 90, 기존 계정은 chage -M 90 <계정>")
def a06():
    f = kv_find("/etc/login.defs", "PASS_MAX_DAYS")
    if not f:
        return BAD, "PASS_MAX_DAYS 미설정 → 만료 없음", [ev("/etc/login.defs", None, "PASS_MAX_DAYS 없음")]
    no, raw, v = f[-1]
    d = to_int(v)
    if d is not None and 0 < d <= 90:
        return GOOD, "PASS_MAX_DAYS %d (신규 계정 기준)" % d, [ev("/etc/login.defs", no, raw)]
    return BAD, "PASS_MAX_DAYS %s → 90일 초과 (신규 계정 기준)" % v, [ev("/etc/login.defs", no, raw)]


@check("A-07", "계정 관리", "세션 종료 시간 설정", "U-54", "하",
       "TMOUT 600초 이하",
       "/etc/profile.d/tmout.sh 에 TMOUT=600; readonly TMOUT; export TMOUT")
def a07():
    files = ["/etc/profile", "/etc/bash.bashrc"] + sorted(glob.glob("/etc/profile.d/*.sh"))
    hits = []
    for p in files:
        for no, raw, s in active(lines_of(p)):
            m = re.search(r"\bTMOUT=(\d+)", s)
            if m:
                hits.append((p, no, raw, int(m.group(1))))
    if not hits:
        return BAD, "TMOUT 설정 없음 → 유휴 세션 무기한 유지", \
            [ev("/etc/profile", None, "TMOUT 없음 (/etc/profile, /etc/bash.bashrc, /etc/profile.d/*.sh 검색)")]
    evs = [ev(p, no, raw) for p, no, raw, v in hits]
    v = hits[-1][3]
    if 0 < v <= 600:
        return GOOD, "TMOUT=%d초" % v, evs
    return BAD, "TMOUT=%d초 → 600초 초과 또는 비활성" % v, evs


# ── 서비스 관리 ──
@check("S-01", "서비스 관리", "Telnet 서비스 비활성화", "U-01", "상",
       "23/tcp 미사용, inetd·xinetd 에 telnet 미등록",
       "systemctl disable --now inetd(xinetd), apt purge telnetd")
def s01():
    hits = port_hits("tcp", {23})
    ih = inetd_hits({"telnet"})
    if hits or ih:
        return BAD, "Telnet 사용 중 (평문 인증)", [ev(h["file"], h["line"], h["text"]) for h in hits] + ih
    return GOOD, "23/tcp 미사용", [port_summary("tcp")]


@check("S-02", "서비스 관리", "FTP 서비스 비활성화", "U-61", "중",
       "21/tcp 미사용 (사용 시 익명 접속 금지)",
       "systemctl disable --now vsftpd, 파일 전송은 SFTP 로 대체")
def s02():
    hits = port_hits("tcp", {21})
    evs = [ev(h["file"], h["line"], h["text"]) for h in hits]
    anon = kv_find("/etc/vsftpd.conf", "anonymous_enable")
    if anon:
        evs.append(ev("/etc/vsftpd.conf", anon[-1][0], anon[-1][1]))
    if hits:
        if anon and anon[-1][2].upper() == "YES":
            return BAD, "FTP 사용 중이며 익명 접속 허용", evs
        return BAD, "FTP 사용 중 (평문 인증) → 필요 여부 확인", evs
    return GOOD, "21/tcp 미사용", [port_summary("tcp")] + evs


@check("S-03", "서비스 관리", "r 계열 서비스 비활성화", "U-21", "상",
       "rexec·rlogin·rsh (512·513·514/tcp) 미사용",
       "inetd.conf 에서 rsh·rlogin·rexec 주석 처리, apt purge rsh-server")
def s03():
    hits = port_hits("tcp", {512, 513, 514})
    ih = inetd_hits({"exec", "login", "shell", "rexec", "rlogin", "rsh"})
    if hits or ih:
        return BAD, "r 계열 서비스 사용 중", [ev(h["file"], h["line"], h["text"]) for h in hits] + ih
    return GOOD, "512·513·514/tcp 미사용", [port_summary("tcp")]


@check("S-04", "서비스 관리", "SNMP 서비스 구동 점검", "U-66", "중",
       "SNMP(161/udp) 미사용, 사용 시 public·private 커뮤니티 금지",
       "systemctl disable --now snmpd, 필요 시 SNMPv3 와 복잡한 커뮤니티명 사용")
def s04():
    hits = port_hits("udp", {161})
    evs = [ev(h["file"], h["line"], h["text"]) for h in hits]
    comm = [ev("/etc/snmp/snmpd.conf", no, raw) for no, raw, s in active(lines_of("/etc/snmp/snmpd.conf"))
            if re.search(r"\b(public|private)\b", s)]
    if hits:
        return BAD, "SNMP 사용 중" + (" (기본 커뮤니티 public/private)" if comm else ""), evs + comm
    return GOOD, "161/udp 미사용", [port_summary("udp")]


@check("S-05", "서비스 관리", "SSH 빈 비밀번호 로그인 금지", "CIS 5.2", "상",
       "PermitEmptyPasswords no (미설정 시 기본값 no)",
       "sshd_config 에 PermitEmptyPasswords no 명시")
def s05():
    if lines_of(SSHD) is None:
        return NA, "SSH 서버 미설치", [ev(SSHD, None, "파일 없음")]
    r = sshd_get("PermitEmptyPasswords")
    if r is None:
        return GOOD, "미설정 → OpenSSH 기본값 no", [ev(SSHD, None, "PermitEmptyPasswords 지시어 없음 (기본값 no)")]
    path, no, raw, v = r
    if v.lower() == "no":
        return GOOD, "빈 비밀번호 로그인 차단", [ev(path, no, raw)]
    return BAD, "PermitEmptyPasswords %s" % v, [ev(path, no, raw)]


# ── 파일 시스템 ──
def perm_item(path, maxmode):
    if not os.path.exists(path):
        return NA, "파일 없음", [ev(path, None, "파일 없음")]
    st, mode, txt = stat_text(path)
    extra = mode & ~maxmode
    evs = [ev(path, None, txt)]
    if st.st_uid == 0 and not extra:
        return GOOD, "소유자 root, 권한 %04o (기준 %04o 이하)" % (mode, maxmode), evs
    why = []
    if st.st_uid != 0:
        why.append("소유자가 root 아님")
    if extra:
        why.append("권한 %04o 가 기준 %04o 초과" % (mode, maxmode))
    return BAD, ", ".join(why), evs


@check("F-01", "파일 시스템", "/etc/passwd 소유자 및 권한", "U-07", "상",
       "소유자 root, 권한 644 이하", "chown root /etc/passwd; chmod 644 /etc/passwd")
def f01():
    return perm_item("/etc/passwd", 0o644)


@check("F-02", "파일 시스템", "/etc/shadow 소유자 및 권한", "U-08", "상",
       "소유자 root, 권한 400 이하", "chown root /etc/shadow; chmod 400 /etc/shadow")
def f02():
    return perm_item("/etc/shadow", 0o400)


@check("F-03", "파일 시스템", "/etc/hosts 소유자 및 권한", "U-09", "상",
       "소유자 root, 권한 600 이하", "chown root /etc/hosts; chmod 600 /etc/hosts")
def f03():
    return perm_item("/etc/hosts", 0o600)


@check("F-04", "파일 시스템", "world writable 파일 점검 (/etc)", "U-15", "상",
       "/etc 아래에 다른 사용자 쓰기 권한(o+w) 파일·디렉터리가 없음 (sticky 디렉터리 제외)",
       "chmod o-w <파일>, 필요한 경우 사유를 문서화")
def f04():
    found, scanned = [], 0
    for root, dirs, files in os.walk("/etc", onerror=lambda e: None):
        for name in dirs + files:
            p = os.path.join(root, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            scanned += 1
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_mode & stat.S_IWOTH and not (stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX):
                found.append(ev(p, None, "lstat() → %s" % stat.filemode(st.st_mode)))
    if found:
        return BAD, "o+w 항목 %d개" % len(found), found[:8]
    return GOOD, "o+w 항목 없음 (%d개 검사)" % scanned, [ev("/etc", None, "os.walk + lstat() %d개 항목 검사, 심볼릭 링크 제외" % scanned)]


@check("F-05", "파일 시스템", "/etc/hosts.equiv, .rhosts 사용 금지", "U-17", "상",
       "파일이 없거나, 있으면 소유자 본인·권한 600 이하·'+' 설정 없음",
       "rm /etc/hosts.equiv ~/.rhosts (r 계열 미사용 시)")
def f05():
    cands = ["/etc/hosts.equiv", "/root/.rhosts"] + sorted(glob.glob("/home/*/.rhosts"))
    evs, bad, unknown = [], [], []
    for p in cands:
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        except PermissionError:
            unknown.append(p)
            continue
        _, mode, txt = stat_text(p)
        evs.append(ev(p, None, txt))
        if mode & 0o077:
            bad.append("%s 권한 %04o" % (p, mode))
        try:
            for no, raw, s in active(lines_of(p)):
                if s.startswith("+"):
                    evs.append(ev(p, no, raw))
                    bad.append("%s '+' 허용" % p)
        except Unreadable:
            pass
    if bad:
        return BAD, "; ".join(bad), evs
    if evs:
        return GOOD, "파일은 있으나 권한·내용 기준 충족", evs
    note = " (%s 는 권한 문제로 확인 못함)" % ", ".join(unknown) if unknown else ""
    return GOOD, "hosts.equiv·.rhosts 없음" + note, [ev(", ".join(cands[:3]) + (" …" if len(cands) > 3 else ""), None, "lstat() → 파일 없음")]


@check("F-06", "파일 시스템", "UMASK 설정", "U-56", "중",
       "UMASK 022 이상 (그룹·기타 쓰기 금지)",
       "login.defs UMASK 022, /etc/profile 에 umask 022")
def f06():
    hits = []
    for no, raw, v in kv_find("/etc/login.defs", "UMASK"):
        hits.append(("/etc/login.defs", no, raw, v))
    for p in ["/etc/profile", "/etc/bash.bashrc"]:
        for no, raw, s in active(lines_of(p)):
            m = re.match(r"umask\s+([0-7]{3,4})\b", s)
            if m:
                hits.append((p, no, raw, m.group(1)))
    if not hits:
        return BAD, "UMASK 설정 없음", [ev("/etc/login.defs", None, "UMASK 없음")]
    evs = [ev(p, no, raw) for p, no, raw, v in hits]
    weak = [v for p, no, raw, v in hits if (to_int(v, 8) or 0) & 0o022 != 0o022]
    if weak:
        return BAD, "UMASK %s → 그룹·기타 쓰기 허용" % ", ".join(weak), evs
    return GOOD, "UMASK %s" % ", ".join(sorted({v for *_, v in hits})), evs


# ───────────────────────── 실행 ─────────────────────────
def run_all():
    results = []
    for c in CHECKS:
        try:
            verdict, reason, evs = c["fn"]()
        except Unreadable as e:
            verdict, reason, evs = ERR, "%s %s → sudo 로 재점검 필요" % (e.path, e.why), [ev(e.path, None, "open() → PermissionError")]
        except Exception as e:  # 점검 하나가 실패해도 나머지는 계속
            verdict, reason, evs = ERR, "점검 중 오류: %s" % e, []
        r = {k: v for k, v in c.items() if k != "fn"}
        r.update(verdict=verdict, reason=reason, evidence=evs)
        results.append(r)
    return results


def host_info(args):
    osname = platform.system()
    for no, raw in lines_of("/etc/os-release") or []:
        if raw.startswith("PRETTY_NAME="):
            osname = raw.split("=", 1)[1].strip('"')
    ip = "-"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # UDP connect 는 패킷을 보내지 않고 출발지 주소만 정한다
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    try:
        up = float(open("/proc/uptime").read().split()[0])
        uptime = "%d일 %d시간" % (up // 86400, up % 86400 // 3600)
    except OSError:
        uptime = "-"
    return {
        "asset_id": args.asset_id, "grade": args.grade, "hostname": socket.gethostname(),
        "os": osname, "kernel": platform.release(), "arch": platform.machine(), "ip": ip, "uptime": uptime,
        "user": pwd.getpwuid(os.geteuid()).pw_name, "root": os.geteuid() == 0,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "version": VERSION,
    }


# ───────────────────────── 결과표 문구 ─────────────────────────
ADMIN = {
    "계정 관리": "계정·비밀번호 정책(복잡성, 사용기간, 잠금 임계값)과 관리자 원격 접속 기준을 보안 정책서에 명시하고, 분기별 계정 현황 검토와 승인 기록을 남겨야 한다.",
    "서비스 관리": "운영에 필요한 서비스와 허용 포트 기준표를 정하고, 신규 서비스 개통 시 승인 절차를 거치며 반기마다 열린 포트를 대조 점검해야 한다.",
    "파일 시스템": "주요 설정 파일의 소유자·권한 기준을 표준 구성 문서로 관리하고, 변경 시 변경관리 절차와 무결성 점검을 수행해야 한다.",
}


def summarize(results, info):
    rows = []
    for cat in CATS:
        rs = [r for r in results if r["cat"] == cat]
        g = sum(r["verdict"] == GOOD for r in rs)
        b = [r for r in rs if r["verdict"] == BAD]
        e = [r for r in rs if r["verdict"] == ERR]
        judged = g + len(b)
        pct = round(g * 100 / judged) if judged else 0
        status = "이행" if judged and not b else ("부분 이행" if pct >= 50 else "미이행")
        if not judged:
            status = "판단 보류"
        admin = ADMIN[cat] + " " + (
            "현재 %s 항목이 정책 기준과 다르므로 담당자와 조치 기한을 정한 조치 계획서를 작성해야 한다." % ", ".join(r["id"] for r in b)
            if b else "현재 점검 항목은 기준과 일치하므로 정기 점검 주기를 유지한다.")
        tech = ["%s %s: %s → %s" % (r["id"], r["title"], r["reason"], r["fix"]) for r in b]
        tech += ["%s %s: %s" % (r["id"], r["title"], r["reason"]) for r in e]
        if not tech:
            tech = ["점검한 %d개 항목 모두 기술 기준 충족" % len(rs)]
        rows.append(dict(cat=cat, total=len(rs), good=g, bad=len(b), err=len(e), pct=pct, status=status, admin=admin, tech=tech))

    g = sum(r["verdict"] == GOOD for r in results)
    b = [r for r in results if r["verdict"] == BAD]
    e = [r for r in results if r["verdict"] == ERR]
    n = sum(r["verdict"] == NA for r in results)
    judged = g + len(b)
    pct = round(g * 100 / judged) if judged else 0
    level = "우수" if pct >= 90 else "보통" if pct >= 70 else "미흡" if pct >= 50 else "취약"
    high = [r for r in b if r["prio"] == "상"]
    days = 30 if "1등급" in info["grade"] else 60 if "2등급" in info["grade"] else 90
    parts = ["%d개 항목 중 양호 %d, 취약 %d, 점검 불가 %d, 해당 없음 %d. 판정한 항목 기준 이행률 %d%%로 보안 수준은 '%s'이다."
             % (len(results), g, len(b), len(e), n, pct, level)]
    if high:
        parts.append("중요도 상 취약 항목 %s 은(는) 자산 중요도 %s 기준에 따라 %d일 안에 우선 조치해야 한다."
                     % (", ".join("%s(%s)" % (r["id"], r["title"]) for r in high), info["grade"], days))
    rest = [r for r in b if r["prio"] != "상"]
    if rest:
        parts.append("나머지 취약 항목 %s 은(는) 다음 정기 점검 전까지 조치한다." % ", ".join(r["id"] for r in rest))
    if e:
        parts.append("점검 불가 %s 은(는) 일반 계정 권한으로 읽을 수 없는 파일이 있어 'sudo python3 check.py' 로 재점검해야 한다."
                     % ", ".join(r["id"] for r in e))
    if not b and not e:
        parts.append("모든 항목이 기준을 충족하므로 현재 설정을 기준선(baseline)으로 보관하고 변경 시 재점검한다.")
    return rows, dict(good=g, bad=len(b), err=len(e), na=n, pct=pct, level=level, text=" ".join(parts))


# ───────────────────────── 콘솔 출력 ─────────────────────────
def print_console(results, info, total):
    tty = sys.stdout.isatty()
    col = {GOOD: "32", BAD: "31", ERR: "33", NA: "90"}
    c = (lambda v, t: "\033[%sm%s\033[0m" % (col[v], t)) if tty else (lambda v, t: t)
    print("■ 점검 대상: %s (%s) · %s · %s" % (info["hostname"], info["asset_id"], info["os"], info["time"]))
    print("■ 실행 계정: %s%s\n" % (info["user"], " (root)" if info["root"] else " (일반 계정: 일부 항목 점검 불가 가능)"))
    for cat in CATS:
        print("[%s]" % cat)
        for r in [r for r in results if r["cat"] == cat]:
            print("  %s %-5s %s  -  %s" % (c(r["verdict"], "[%s]" % r["verdict"]), r["id"], r["title"], r["reason"]))
            for e in r["evidence"]:
                loc = e["file"] + (":%s" % e["line"] if e["line"] else "")
                print("        └ %s  %s" % (loc, e["text"]))
        print()
    print("■ 양호 %d · 취약 %d · 점검 불가 %d · 해당 없음 %d · 이행률 %d%% (%s)"
          % (total["good"], total["bad"], total["err"], total["na"], total["pct"], total["level"]))


# ───────────────────────── HTML 결과서 ─────────────────────────
def h(s):
    return html.escape(str(s), quote=True)


VCLS = {GOOD: "ok", BAD: "bad", ERR: "err", NA: "na"}


def render_html(results, info, rows, total):
    sections = []
    for cat in CATS:
        trs = []
        for r in [r for r in results if r["cat"] == cat]:
            evs = "".join(
                '<li><span class="loc">%s%s</span><code>%s</code></li>' % (
                    h(e["file"]), ('<b>:%s</b>' % h(e["line"])) if e["line"] else ' <i>(stat/검색)</i>', h(e["text"]))
                for e in r["evidence"]) or '<li><i>근거 없음</i></li>'
            trs.append(
                '<tr><td class="id">%s<span class="ref">%s</span></td>'
                '<td class="item"><b>%s</b><span class="crit">기준: %s</span><span class="prio p%s">중요도 %s</span></td>'
                '<td><span class="v %s">%s</span></td>'
                '<td class="evd"><p class="why">%s</p><ul>%s</ul>%s</td></tr>' % (
                    h(r["id"]), h(r["ref"]), h(r["title"]), h(r["crit"]), {"상": "h", "중": "m", "하": "l"}[r["prio"]], h(r["prio"]),
                    VCLS[r["verdict"]], h(r["verdict"]), h(r["reason"]), evs,
                    ('<p class="fix">조치: %s</p>' % h(r["fix"])) if r["verdict"] == BAD else ""))
        rs = [r for r in results if r["cat"] == cat]
        sections.append(
            '<section class="cat"><header><h2>%s</h2><span>%d개 항목 · 양호 %d · 취약 %d</span></header>'
            '<div class="tscroll"><table class="res"><thead><tr><th>ID</th><th>점검 항목</th><th>판정</th><th>판정 근거 (읽은 파일:줄)</th></tr></thead>'
            '<tbody>%s</tbody></table></div></section>' % (
                h(cat), len(rs), sum(r["verdict"] == GOOD for r in rs), sum(r["verdict"] == BAD for r in rs), "".join(trs)))

    srows = "".join(
        '<tr><th scope="row">%s<span>%d개 중 양호 %d</span></th><td>%s</td><td><ul>%s</ul></td>'
        '<td class="st"><span class="s %s">%s</span><span class="pct">%d%%</span></td></tr>' % (
            h(r["cat"]), r["total"], r["good"], h(r["admin"]), "".join("<li>%s</li>" % h(t) for t in r["tech"]),
            {"이행": "ok", "부분 이행": "part", "미이행": "bad", "판단 보류": "na"}[r["status"]], h(r["status"]), r["pct"])
        for r in rows)

    return TEMPLATE.substitute(
        host=h(info["hostname"]), asset=h(info["asset_id"]), grade=h(info["grade"]), os=h(info["os"]),
        kernel=h(info["kernel"] + " · " + info["arch"]), ip=h(info["ip"]), uptime=h(info["uptime"]),
        user=h(info["user"] + (" (root)" if info["root"] else " (일반 계정)")), time=h(info["time"]), version=h(info["version"]),
        n=len(results), good=total["good"], bad=total["bad"], err=total["err"], na=total["na"], pct=total["pct"], level=h(total["level"]),
        rootnote="" if info["root"] else '<p class="warnline">일반 계정으로 실행했습니다. root 전용 파일을 읽어야 하는 항목은 "점검 불가"로 표시되며, <code>sudo python3 check.py</code> 로 다시 실행하면 판정됩니다.</p>',
        sections="".join(sections), srows=srows, verdict=h(total["text"]))


TEMPLATE = Template(r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="author" content="너구리 (ㄴㄱㄹ)">
<title>보안 점검 결과서 · $host</title>
<!-- check.py v$version 가 생성한 결과서 · 제작: 너구리 (ㄴㄱㄹ) -->
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans+KR:wght@400;500;600;700&display=swap">
<style>
/* 문서형 결과서: 표지 정보 → 요약 → 분류별 결과 → 점검 결과표 */
:root{--bg:#EDF1F3;--paper:#FFFFFF;--sunken:#E6ECEF;--ink:#14212A;--muted:#566874;--line:#CDD7DC;--accent:#0D6B70;
 --ok:#2E7D46;--ok-soft:#DCEFE2;--bad:#B83A26;--bad-soft:#F6DFDA;--err:#A86B0C;--err-soft:#F7EBD3;--na:#6B7B86;--na-soft:#E3E9EC;
 --f-body:"IBM Plex Sans KR",system-ui,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;--f-mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0F171C;--paper:#16222A;--sunken:#1D2B34;--ink:#E1EAEE;--muted:#93A6B1;--line:#2A3A44;--accent:#4DB6B4;
 --ok:#6CC488;--ok-soft:#173322;--bad:#F0806B;--bad-soft:#3E1D17;--err:#E2B04F;--err-soft:#3A2D12;--na:#93A6B1;--na-soft:#1D2B34;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0F171C;--paper:#16222A;--sunken:#1D2B34;--ink:#E1EAEE;--muted:#93A6B1;--line:#2A3A44;--accent:#4DB6B4;
 --ok:#6CC488;--ok-soft:#173322;--bad:#F0806B;--bad-soft:#3E1D17;--err:#E2B04F;--err-soft:#3A2D12;--na:#93A6B1;--na-soft:#1D2B34;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--f-body)}
.doc{max-width:1120px;margin:0 auto;padding-block:28px 48px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
h1,h2{margin:0;line-height:1.3;text-wrap:balance}
code{font-family:var(--f-mono)}
.cover{background:var(--paper);border:1px solid var(--line);border-radius:8px;padding:22px 24px}
.eyebrow{font-size:12px;letter-spacing:.08em;color:var(--muted);font-weight:600}
.cover h1{font-size:24px;margin:4px 0 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.mark{display:inline-grid;place-items:center;width:32px;height:32px;border-radius:50%;background:var(--ink);color:var(--paper);font-size:11px;font-weight:700}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:0;border-top:1px solid var(--line)}
.meta div{display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--line);min-width:0;padding-right:16px}
.meta dt{width:6.5em;flex:none;color:var(--muted);font-size:13px}
.meta dd{margin:0;font-family:var(--f-mono);font-size:13.5px;overflow-wrap:anywhere}
.sum{display:flex;flex-wrap:wrap;gap:10px 28px;align-items:baseline;margin-top:18px}
.sum .big{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums}
.sum .big small{font-size:14px;color:var(--muted);font-weight:500;margin-left:6px}
.sum span{font-variant-numeric:tabular-nums;font-size:14px}
.sum i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.warnline{margin:14px 0 0;padding:8px 12px;background:var(--err-soft);border-left:3px solid var(--err);font-size:13.5px}
.cat{margin-top:28px}
.cat header{display:flex;justify-content:space-between;align-items:baseline;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.cat h2{font-size:18px}
.cat header span{color:var(--muted);font-size:13px}
.tscroll{overflow-x:auto;background:var(--paper);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}
.res{min-width:760px}
th,td{text-align:left;vertical-align:top;padding:12px 14px;border-bottom:1px solid var(--line)}
thead th{font-size:12.5px;color:var(--muted);background:var(--sunken);font-weight:600;padding-block:8px}
tbody tr:last-child>*{border-bottom:0}
.id{font-family:var(--f-mono);font-weight:600;white-space:nowrap;width:84px}
.ref{display:block;font-weight:400;font-size:11.5px;color:var(--muted)}
.item{width:28%}
.item b{display:block}
.crit{display:block;font-size:12.5px;color:var(--muted);margin-top:2px}
.prio{display:inline-block;font-size:11px;margin-top:6px;padding:0 6px;border:1px solid var(--line);border-radius:4px;color:var(--muted)}
.prio.ph{border-color:var(--bad);color:var(--bad)}
.v{display:inline-block;font-size:12.5px;font-weight:700;padding:2px 10px;border-radius:999px;white-space:nowrap}
.v.ok{background:var(--ok-soft);color:var(--ok)}.v.bad{background:var(--bad-soft);color:var(--bad)}.v.err{background:var(--err-soft);color:var(--err)}.v.na{background:var(--na-soft);color:var(--na)}
.evd{min-width:0}
.why{margin:0 0 6px;font-weight:500}
.evd ul{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:4px}
.evd li{font-size:12.5px;background:var(--sunken);border-radius:5px;padding:5px 9px;overflow-wrap:anywhere}
.loc{font-family:var(--f-mono);color:var(--accent);margin-right:8px;font-weight:500}
.loc i{color:var(--muted);font-style:normal}
.evd code{font-size:12.5px;white-space:pre-wrap}
.fix{margin:8px 0 0;font-size:13px;color:var(--bad)}
.final{margin-top:36px}
.final h2{font-size:18px;margin-bottom:8px}
.final table{min-width:820px}
.final thead th{text-align:center}
.final tbody th{width:120px;font-size:14px;background:var(--sunken)}
.final tbody th span{display:block;font-weight:400;font-size:12px;color:var(--muted)}
.final td{font-size:13.5px}
.final td:nth-child(2){width:32%}
.final td ul{margin:0;padding-left:18px}
.final .st{text-align:center;width:110px}
.s{display:inline-block;font-weight:700;font-size:13px;padding:3px 10px;border-radius:999px}
.s.ok{background:var(--ok-soft);color:var(--ok)}.s.part{background:var(--err-soft);color:var(--err)}.s.bad{background:var(--bad-soft);color:var(--bad)}.s.na{background:var(--na-soft);color:var(--na)}
.pct{display:block;font-family:var(--f-mono);font-size:12px;color:var(--muted);margin-top:4px}
.total th{background:var(--ink)!important;color:var(--paper)}
.total td{font-size:14px;line-height:1.75}
.opinion td{min-height:48px;color:var(--muted)}
.opinion td:focus{color:var(--ink);outline:2px solid var(--accent)}
.sign{margin-top:28px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px}
</style>
</head>
<body>
<div class="doc">
<section class="cover">
  <div class="eyebrow">리눅스 서버 보안 점검 · 읽기 전용</div>
  <h1><span class="mark" title="제작: 너구리">ㄴㄱㄹ</span>보안 점검 결과서</h1>
  <dl class="meta">
    <div><dt>자산번호</dt><dd>$asset</dd></div>
    <div><dt>자산 중요도</dt><dd>$grade</dd></div>
    <div><dt>호스트명</dt><dd>$host</dd></div>
    <div><dt>IP 주소</dt><dd>$ip</dd></div>
    <div><dt>운영체제</dt><dd>$os</dd></div>
    <div><dt>커널</dt><dd>$kernel</dd></div>
    <div><dt>점검 일시</dt><dd>$time</dd></div>
    <div><dt>가동 시간</dt><dd>$uptime</dd></div>
    <div><dt>실행 계정</dt><dd>$user</dd></div>
    <div><dt>점검 도구</dt><dd>check.py v$version</dd></div>
  </dl>
  <div class="sum">
    <div class="big">$pct%<small>이행률 · $level</small></div>
    <span><i style="background:var(--ok)"></i>양호 $good</span>
    <span><i style="background:var(--bad)"></i>취약 $bad</span>
    <span><i style="background:var(--err)"></i>점검 불가 $err</span>
    <span><i style="background:var(--na)"></i>해당 없음 $na</span>
    <span style="color:var(--muted)">전체 $n개 항목 · 계정 7 · 서비스 5 · 파일 시스템 6</span>
  </div>
  $rootnote
</section>

$sections

<section class="final">
  <h2>점검 결과표</h2>
  <div class="tscroll"><table>
    <thead><tr><th>구분</th><th>관리적 관점</th><th>기술적 관점</th><th>이행 여부</th></tr></thead>
    <tbody>
      $srows
      <tr class="total"><th scope="row">총평</th><td colspan="3">$verdict</td></tr>
      <tr class="opinion"><th scope="row">점검자 의견</th><td colspan="3" contenteditable="true">(클릭해서 의견을 적을 수 있습니다. 저장은 브라우저 저장 기능을 쓰세요.)</td></tr>
    </tbody>
  </table></div>
</section>

<footer class="sign"><span>제작 <b>너구리 (ㄴㄱㄹ)</b></span><span>check.py v$version · 설정 변경 없이 파일 읽기와 stat 만으로 점검</span></footer>
</div>
</body>
</html>
""")


def main():
    ap = argparse.ArgumentParser(description="리눅스 서버 읽기 전용 보안 점검 (18개 항목)")
    ap.add_argument("--asset-id", default="SRV-001", help="자산 관리 대장의 자산번호")
    ap.add_argument("--grade", default="2등급(중)", help="자산 중요도 등급 (assets.html 에서 계산)")
    ap.add_argument("--out", default="report.html", help="HTML 결과서 경로")
    ap.add_argument("--json", help="JSON 결과 경로 (선택)")
    args = ap.parse_args()

    info = host_info(args)
    results = run_all()
    rows, total = summarize(results, info)
    print_console(results, info, total)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render_html(results, info, rows, total))
    print("■ 결과서: %s" % os.path.abspath(args.out))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"info": info, "results": results, "summary": rows, "total": total}, f, ensure_ascii=False, indent=2)
        print("■ JSON: %s" % os.path.abspath(args.json))


if __name__ == "__main__":
    main()
