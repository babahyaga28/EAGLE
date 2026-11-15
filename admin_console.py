#!/usr/bin/env python3
"""
admin_console.py - Konsol Komandan/Admin EAGLE.

  python admin_console.py add-user  budi            # buat penyidik (minta kata sandi)
  python admin_console.py add-user  komandan --role admin
  python admin_console.py issue-otp budi            # terbitkan OTP 8 digit, berlaku 10 menit, sekali pakai
  python admin_console.py list                      # daftar pengguna
  python admin_console.py unlock budi               # buka kunci akun
  python admin_console.py verify-audit              # periksa keutuhan log chain-of-custody

Data disimpan di $FORENSIC_HOME (default ~/.eagle; instalasi lama di ~/.forensic_triage tetap terbaca).
"""
import argparse
import getpass
import sys
import time
from pathlib import Path

import osint_core as core


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--home", default=str(core.HOME))
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add-user"); a.add_argument("username"); a.add_argument("--role", default="penyidik", choices=["penyidik", "admin"])
    o = sub.add_parser("issue-otp"); o.add_argument("username"); o.add_argument("--ttl", type=int, default=core.OTP_TTL // 60, help="menit")
    sub.add_parser("list")
    u = sub.add_parser("unlock"); u.add_argument("username")
    sub.add_parser("verify-audit")
    rc = sub.add_parser("recovery-code"); rc.add_argument("username")
    r = sub.add_parser("reset-password"); r.add_argument("username")
    d = sub.add_parser("disable"); d.add_argument("username")
    e = sub.add_parser("enable"); e.add_argument("username")
    args = ap.parse_args(argv)
    home = Path(args.home)
    store = core.AuthStore(home)

    try:
        if args.cmd == "add-user":
            pw = getpass.getpass("Kata sandi: ")
            if pw != getpass.getpass("Ulangi    : "):
                print("Kata sandi tidak sama."); return 1
            store.add_user(args.username, pw, args.role)
            core.AuditLog(home / "audit.jsonl").append("admin-console", "ADD_USER", {"user": args.username, "role": args.role})
            print(f"Pengguna '{args.username}' dibuat ({args.role}).")
            if args.role == "admin":
                rec = store.set_recovery(args.username)
                core.AuditLog(home / "audit.jsonl").append("admin-console", "NEW_RECOVERY", {"user": args.username})
                print(f"\n  KODE PEMULIHAN: {rec}\n  Simpan di tempat aman (cetak/brankas). Tampil SEKALI.\n")
        elif args.cmd == "issue-otp":
            code = store.issue_otp(args.username, args.ttl * 60)
            core.AuditLog(home / "audit.jsonl").append("admin-console", "ISSUE_OTP", {"user": args.username, "ttl_menit": args.ttl})
            print(f"\n  OTP untuk {args.username}: {code}\n  Berlaku {args.ttl} menit, SEKALI PAKAI. Sampaikan lewat kanal terpisah.\n")
        elif args.cmd == "list":
            for name, d in store.list_users().items():
                lock = "NONAKTIF" if d["disabled"] else ("TERKUNCI" if d["locked_until"] > time.time() else "aktif")
                print(f"{name:20s} {d['role']:10s} {lock}")
        elif args.cmd == "unlock":
            store.unlock(args.username); print("Dibuka.")
        elif args.cmd in ("disable", "enable"):
            store.set_disabled(args.username, args.cmd == "disable")
            core.AuditLog(home / "audit.jsonl").append("admin-console", args.cmd.upper(), {"user": args.username})
            print("Selesai.")
        elif args.cmd == "reset-password":
            pw = getpass.getpass("Kata sandi baru: ")
            if pw != getpass.getpass("Ulangi          : "):
                print("Kata sandi tidak sama."); return 1
            store.set_password(args.username, pw)
            core.AuditLog(home / "audit.jsonl").append("admin-console", "RESET_PASSWORD", {"user": args.username})
            print("Kata sandi diganti; OTP lama dicabut.")
        elif args.cmd == "recovery-code":
            rec = store.set_recovery(args.username)
            core.AuditLog(home / "audit.jsonl").append("admin-console", "NEW_RECOVERY", {"user": args.username})
            print(f"\n  KODE PEMULIHAN BARU: {rec}\n  Kode lama tidak berlaku. Simpan di tempat aman.\n")
        elif args.cmd == "verify-audit":
            ok, n, bad = core.AuditLog(home / "audit.jsonl").verify()
            print(f"{n} entri - " + ("UTUH" if ok else f"RUSAK mulai entri #{bad}"))
            return 0 if ok else 2
    except (ValueError, TimeoutError) as e:
        print(f"Gagal: {e}"); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
