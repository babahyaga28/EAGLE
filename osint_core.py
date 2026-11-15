#!/usr/bin/env python3
"""
osint_core.py - Mesin inti EAGLE (Forensic Triage & OSINT Platform).

Tanpa dependensi wajib selain: Pillow, numpy, opencv-python, reportlab.
Gemini dipanggil lewat REST (urllib) sehingga tidak butuh SDK.
Semua logika ada di sini; GUI (triage_app.py) hanya lapisan tipis.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import html
import json
import math
import os
import re
import secrets
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterable, Optional
from xml.sax.saxutils import escape as xesc

from face_compare import MAX_PHOTOS, fmt_num, fmt_pct  # noqa: E402

APP_NAME = "EAGLE"
TAGLINE = "Forensic Triage & OSINT"


def _default_home() -> Path:
    new, legacy = Path.home() / ".eagle", Path.home() / ".forensic_triage"
    return legacy if (legacy.exists() and not new.exists()) else new      # instalasi lama tetap terbaca


HOME = Path(os.environ.get("FORENSIC_HOME", str(_default_home())))

# ----------------------------------------------------------------------------
# Utilitas
# ----------------------------------------------------------------------------

def visible(t) -> str:
    """Tampilkan karakter kontrol/bidi secara eksplisit (mis. [U+202E]) agar penyamaran nama berkas terlihat."""
    import unicodedata
    return "".join(f"[U+{ord(ch):04X}]" if unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\n\t" else ch for ch in str(t))


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


@contextlib.contextmanager
def _locked(path: Path, timeout: float = 10.0):
    """Kunci berkas sederhana (O_EXCL) agar admin & aplikasi tidak saling menimpa."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    t0 = time.time()
    while True:
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            # kunci basi (>30 dtk) dianggap sisa proses yang crash
            try:
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink()
                    continue
            except OSError:
                pass
            if time.time() - t0 > timeout:
                raise TimeoutError(f"Tidak bisa mengunci {path}")
            time.sleep(0.05)
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            lock.unlink()


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


# ----------------------------------------------------------------------------
# 1. Keamanan Zero-Trust: kata sandi + OTP sekali-pakai dari Komandan/Admin
# ----------------------------------------------------------------------------

PBKDF2_ITERS = 600_000
MAX_FAILS = 5
LOCK_SECS = 15 * 60
OTP_TTL = 10 * 60
MIN_PASSWORD = 10


class AuthError(Exception):
    pass


def _pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)


class AuthStore:
    """
    users.json    : {username: {salt, hash, role, fails, locked_until}}
    otp_pool.json : daftar OTP yang diterbitkan Admin. Hanya HASH-nya yang disimpan,
                    sekali pakai, kedaluwarsa, dan terikat ke satu username.
    """

    def __init__(self, home: Path = HOME):
        self.home = Path(home)
        self.users_f = self.home / "users.json"
        self.otp_f = self.home / "otp_pool.json"

    # --- administrasi ---------------------------------------------------
    def add_user(self, username: str, password: str, role: str = "penyidik") -> None:
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{3,32}", username):
            raise ValueError("Username 3-32 karakter: huruf, angka, _ . -")
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"Kata sandi minimal {MIN_PASSWORD} karakter")
        if role not in ("penyidik", "admin"):
            raise ValueError("Role harus 'penyidik' atau 'admin'")
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            if username in users:
                raise ValueError("Username sudah ada (gunakan reset kata sandi)")
            salt = secrets.token_bytes(16)
            users[username] = {"salt": salt.hex(), "hash": _pbkdf2(password, salt).hex(), "role": role,
                               "fails": 0, "locked_until": 0, "disabled": False,
                               "created": utcnow(), "last_login": ""}
            _write_json(self.users_f, users)

    def has_users(self) -> bool:
        return bool(_read_json(self.users_f, {}))

    def list_users(self) -> dict:
        return {u: {"role": d["role"], "locked_until": d.get("locked_until", 0), "fails": d.get("fails", 0),
                    "disabled": bool(d.get("disabled")), "last_login": d.get("last_login", ""),
                    "created": d.get("created", ""), "has_recovery": bool(d.get("rec_hash"))}
                for u, d in _read_json(self.users_f, {}).items()}

    def _mutate(self, username: str, fn) -> None:
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            if username not in users:
                raise ValueError("Username tidak ditemukan")
            fn(users[username])
            _write_json(self.users_f, users)

    def set_password(self, username: str, password: str) -> None:
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"Kata sandi minimal {MIN_PASSWORD} karakter")
        salt = secrets.token_bytes(16)
        self._mutate(username, lambda u: u.update(salt=salt.hex(), hash=_pbkdf2(password, salt).hex(),
                                                   fails=0, locked_until=0))
        self.revoke_user_otps(username)          # OTP lama tak berlaku setelah reset

    def set_disabled(self, username: str, flag: bool) -> None:
        self._mutate(username, lambda u: u.update(disabled=bool(flag)))
        if flag:
            self.revoke_user_otps(username)

    def set_role(self, username: str, role: str) -> None:
        if role not in ("penyidik", "admin"):
            raise ValueError("Role harus 'penyidik' atau 'admin'")
        def apply(u):
            u["role"] = role
            if role != "admin":
                u.pop("rec_hash", None)
                u.pop("rec_salt", None)
        self._mutate(username, apply)

    def delete_user(self, username: str) -> None:
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            if users.pop(username, None) is None:
                raise ValueError("Username tidak ditemukan")
            _write_json(self.users_f, users)
        self.revoke_user_otps(username)

    def pending_otps(self) -> list[dict]:
        """OTP yang masih berlaku. Kode aslinya tidak pernah bisa dibaca ulang (hanya hash tersimpan)."""
        now = time.time()
        return [{"id": e["salt"], "user": e["user"], "exp": e["exp"]}
                for e in _read_json(self.otp_f, []) if e["exp"] > now]

    def revoke_otp(self, otp_id: str) -> bool:
        with _locked(self.otp_f):
            pool = _read_json(self.otp_f, [])
            keep = [e for e in pool if e["salt"] != otp_id]
            _write_json(self.otp_f, keep)
            return len(keep) != len(pool)

    def revoke_user_otps(self, username: str) -> None:
        with _locked(self.otp_f):
            _write_json(self.otp_f, [e for e in _read_json(self.otp_f, []) if e["user"] != username])

    def unlock(self, username: str) -> None:
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            if username in users:
                users[username].update(fails=0, locked_until=0)
                _write_json(self.users_f, users)

    def issue_otp(self, username: str, ttl: int = OTP_TTL) -> str:
        if username not in _read_json(self.users_f, {}):
            raise ValueError("Username tidak ditemukan")
        code = f"{secrets.randbelow(10**8):08d}"
        salt = secrets.token_bytes(8)
        entry = {"user": username, "salt": salt.hex(),
                 "h": hashlib.sha256(salt + code.encode()).hexdigest(),
                 "exp": time.time() + ttl}
        with _locked(self.otp_f):
            pool = [e for e in _read_json(self.otp_f, []) if e["exp"] > time.time()]
            pool.append(entry)
            _write_json(self.otp_f, pool)
        return code

    # --- otentikasi -----------------------------------------------------
    def authenticate(self, username: str, password: str, otp: str) -> str:
        generic = AuthError("Kredensial atau OTP tidak valid")
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            u = users.get(username)
            if u is None:                      # samakan waktu respons
                _pbkdf2(password, b"\0" * 16)
                raise generic
            now = time.time()
            if u.get("disabled"):
                _pbkdf2(password, b"\0" * 16)
                raise generic
            if u.get("locked_until", 0) > now:
                mins = int((u["locked_until"] - now) // 60) + 1
                raise AuthError(f"Akun dikunci sementara (~{mins} menit). Hubungi Admin.")
            pw_ok = hmac.compare_digest(bytes.fromhex(u["hash"]), _pbkdf2(password, bytes.fromhex(u["salt"])))
            otp_ok = pw_ok and self._consume_otp(username, otp.strip())
            if pw_ok and otp_ok:
                u.update(fails=0, locked_until=0, last_login=utcnow())
                _write_json(self.users_f, users)
                return u["role"]
            u["fails"] = u.get("fails", 0) + 1
            if u["fails"] >= MAX_FAILS:
                u["locked_until"] = now + LOCK_SECS
                u["fails"] = 0
            _write_json(self.users_f, users)
            raise generic

    # --- kode pemulihan Admin (break-glass) ------------------------------
    _REC_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # tanpa huruf/angka yang mudah tertukar

    def _new_recovery(self, u: dict) -> str:
        raw = "".join(secrets.choice(self._REC_ALPHA) for _ in range(20))   # ~100 bit
        salt = secrets.token_bytes(16)
        u.update(rec_salt=salt.hex(), rec_hash=_pbkdf2(raw, salt).hex(), rec_fails=0, rec_locked=0)
        return "-".join(raw[i:i + 4] for i in range(0, 20, 4))

    def set_recovery(self, username: str) -> str:
        """Buat/ganti kode pemulihan (hanya akun Admin). Kode ditampilkan SEKALI; yang tersimpan hanya hash."""
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            u = users.get(username)
            if not u or u["role"] != "admin":
                raise ValueError("Kode pemulihan hanya untuk akun Admin")
            code = self._new_recovery(u)
            _write_json(self.users_f, users)
        return code

    def recover_admin(self, username: str, code: str, new_password: str) -> tuple[str, str]:
        """Pemulihan darurat: kode pemulihan -> sandi baru + buka kunci + OTP baru + kode pemulihan baru."""
        generic = AuthError("Pemulihan gagal: data tidak valid atau akses dibatasi")
        if len(new_password) < MIN_PASSWORD:
            raise ValueError(f"Kata sandi baru minimal {MIN_PASSWORD} karakter")
        norm = re.sub(r"[^A-Z0-9]", "", (code or "").upper())
        with _locked(self.users_f):
            users = _read_json(self.users_f, {})
            u, now = users.get(username), time.time()
            if u is None or u["role"] != "admin" or u.get("disabled") or not u.get("rec_hash"):
                _pbkdf2(norm, b"\0" * 16)
                raise generic
            if u.get("rec_locked", 0) > now:
                raise generic
            if not hmac.compare_digest(bytes.fromhex(u["rec_hash"]), _pbkdf2(norm, bytes.fromhex(u["rec_salt"]))):
                u["rec_fails"] = u.get("rec_fails", 0) + 1
                if u["rec_fails"] >= MAX_FAILS:
                    u["rec_locked"], u["rec_fails"] = now + LOCK_SECS, 0
                _write_json(self.users_f, users)
                raise generic
            salt = secrets.token_bytes(16)
            u.update(salt=salt.hex(), hash=_pbkdf2(new_password, salt).hex(), fails=0, locked_until=0)
            new_code = self._new_recovery(u)             # kode lama langsung hangus
            _write_json(self.users_f, users)
        self.revoke_user_otps(username)
        return self.issue_otp(username), new_code

    def _consume_otp(self, username: str, code: str) -> bool:
        if not re.fullmatch(r"\d{8}", code):
            return False
        with _locked(self.otp_f):
            pool = _read_json(self.otp_f, [])
            now, hit = time.time(), None
            for e in pool:
                if e["user"] != username or e["exp"] <= now:
                    continue
                h = hashlib.sha256(bytes.fromhex(e["salt"]) + code.encode()).hexdigest()
                if hmac.compare_digest(h, e["h"]):
                    hit = e
                    break
            if hit is None:
                return False
            pool.remove(hit)                   # sekali pakai
            _write_json(self.otp_f, [e for e in pool if e["exp"] > now])
            return True


class OtpRequests:
    """
    Permintaan OTP yang disetujui Admin dari dashboard (tanpa terminal, tanpa telepon-sebut-kode).

    1. Penyidik menekan "Minta OTP": muncul KODE VERIFIKASI 6 digit di layarnya (hanya di memori).
    2. Penyidik menghubungi Admin dan menyebutkan kode verifikasi itu.
    3. Admin mengetik kode verifikasi tsb saat menyetujui -> terbukti orang di layar = orang yang dihubungi.
    4. OTP dienkripsi dengan kunci turunan kode verifikasi; hanya layar penyidik yang bisa membukanya,
       lalu rekaman dihapus (baca-sekali). OTP TIDAK pernah tersimpan sebagai teks biasa.
    """
    PENDING_TTL = 10 * 60
    MIN_GAP = 20
    MAX_PENDING = 50
    MAX_TRIES = 3
    ITERS = 300_000

    def __init__(self, home: Path = HOME):
        self.home = Path(home)
        self.f = self.home / "otp_requests.json"

    def _key(self, vcode: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", re.sub(r"\D", "", vcode or "").encode(), salt, self.ITERS)

    def _load(self) -> list[dict]:
        now = time.time()
        return [r for r in _read_json(self.f, []) if r["exp"] > now]

    @staticmethod
    def _mac(key: bytes, tag: bytes, data: bytes = b"") -> str:
        return hmac.new(key, tag + data, hashlib.sha256).hexdigest()

    # --- sisi penyidik --------------------------------------------------
    def create(self, username: str) -> tuple[str, str]:
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{3,32}", username):
            raise ValueError("Username tidak valid")
        with _locked(self.f):
            rows, now = self._load(), time.time()
            if any(r["user"] == username and now - r["created"] < self.MIN_GAP for r in rows):
                raise ValueError(f"Tunggu {self.MIN_GAP} detik sebelum meminta lagi")
            rows = [r for r in rows if r["user"] != username]
            if len(rows) >= self.MAX_PENDING:
                raise ValueError("Antrean permintaan penuh. Hubungi Admin.")
            rid, vcode, salt = secrets.token_hex(4), f"{secrets.randbelow(10**6):06d}", secrets.token_bytes(16)
            key = self._key(vcode, salt)
            rows.append({"rid": rid, "user": username, "salt": salt.hex(), "vcheck": self._mac(key, b"check"),
                         "created": now, "exp": now + self.PENDING_TTL, "status": "menunggu", "tries": 0})
            _write_json(self.f, rows)
        return rid, vcode          # TIDAK mengungkap apakah username terdaftar

    def poll(self, rid: str, vcode: str) -> dict:
        r = next((x for x in self._load() if x["rid"] == rid), None)
        if r is None:
            return {"status": "kedaluwarsa"}
        if r["status"] == "menunggu":
            return {"status": "menunggu", "sisa": int(r["exp"] - time.time())}
        with _locked(self.f):
            rows = self._load()
            r = next((x for x in rows if x["rid"] == rid), None)
            if r is None:
                return {"status": "kedaluwarsa"}
            if r["status"] == "ditolak":
                rows.remove(r)
                _write_json(self.f, rows)
                return {"status": "ditolak"}
            if r["status"] != "disetujui":
                return {"status": "menunggu", "sisa": int(r["exp"] - time.time())}
            key = self._key(vcode, bytes.fromhex(r["salt"]))
            cipher = bytes.fromhex(r["cipher"])
            if not hmac.compare_digest(self._mac(key, b"mac", cipher), r["mac"]):
                return {"status": "tidak_cocok"}
            stream = hmac.new(key, b"otp", hashlib.sha256).digest()[:len(cipher)]
            otp = bytes(a ^ b for a, b in zip(cipher, stream)).decode()
            rows.remove(r)                                   # baca-sekali
            _write_json(self.f, rows)
            return {"status": "disetujui", "otp": otp}

    # --- sisi admin -----------------------------------------------------
    def list_pending(self) -> list[dict]:
        return [{"rid": r["rid"], "user": r["user"], "created": r["created"], "exp": r["exp"], "tries": r["tries"]}
                for r in self._load() if r["status"] == "menunggu"]

    def approve(self, rid: str, vcode: str, store: "AuthStore", ttl_minutes: int) -> str:
        with _locked(self.f):
            rows = self._load()
            r = next((x for x in rows if x["rid"] == rid and x["status"] == "menunggu"), None)
            if r is None:
                raise ValueError("Permintaan tidak ditemukan, kedaluwarsa, atau sudah diproses")
            key = self._key(vcode, bytes.fromhex(r["salt"]))
            if not hmac.compare_digest(self._mac(key, b"check"), r["vcheck"]):
                r["tries"] += 1
                left = self.MAX_TRIES - r["tries"]
                if left <= 0:
                    r["status"] = "ditolak"
                _write_json(self.f, rows)
                raise ValueError("Kode verifikasi tidak cocok. " + (f"Sisa {left} percobaan." if left > 0 else "Permintaan ditolak otomatis."))
            d = store.list_users().get(r["user"])
            if d is None:
                raise ValueError("Pengguna tidak terdaftar")
            if d["disabled"]:
                raise ValueError("Akun dinonaktifkan")
            code = store.issue_otp(r["user"], ttl_minutes * 60)
            stream = hmac.new(key, b"otp", hashlib.sha256).digest()[:len(code)]
            cipher = bytes(a ^ b for a, b in zip(code.encode(), stream))
            r.update(status="disetujui", cipher=cipher.hex(), mac=self._mac(key, b"mac", cipher),
                     exp=time.time() + ttl_minutes * 60)
            _write_json(self.f, rows)
            return r["user"]

    def reject(self, rid: str) -> bool:
        with _locked(self.f):
            rows = self._load()
            r = next((x for x in rows if x["rid"] == rid and x["status"] == "menunggu"), None)
            if r is None:
                return False
            r["status"] = "ditolak"
            _write_json(self.f, rows)
            return True


# ----------------------------------------------------------------------------
# 2. Chain of Custody: log audit berantai-hash (tamper-evident)
# ----------------------------------------------------------------------------

class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: Path):
        self.path = Path(path)

    @staticmethod
    def _digest(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        out.append({"corrupt": line})
        return out

    def append(self, actor: str, action: str, detail: Optional[dict] = None) -> dict:
        with _locked(self.path):
            rows = self.read()
            prev = rows[-1].get("hash", self.GENESIS) if rows else self.GENESIS
            e = {"ts": utcnow(), "actor": actor, "action": action, "detail": detail or {}, "prev": prev}
            e["hash"] = self._digest(e)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
        return e

    def verify(self) -> tuple[bool, int, Optional[int]]:
        """(utuh?, jumlah entri, indeks entri pertama yang rusak)"""
        prev = self.GENESIS
        rows = self.read()
        for i, e in enumerate(rows):
            if "corrupt" in e or e.get("prev") != prev or e.get("hash") != self._digest(e):
                return False, len(rows), i
            prev = e["hash"]
        return True, len(rows), None


# ----------------------------------------------------------------------------
# 3. Akuisisi read-only + hash MD5 & SHA-256 + deteksi anomali
# ----------------------------------------------------------------------------

SIGS = [  # (kind, magic, offset)
    ("pe", b"MZ", 0), ("elf", b"\x7fELF", 0),
    ("macho", b"\xcf\xfa\xed\xfe", 0), ("macho", b"\xce\xfa\xed\xfe", 0),
    ("macho", b"\xfe\xed\xfa\xcf", 0), ("macho", b"\xfe\xed\xfa\xce", 0),
    ("class", b"\xca\xfe\xba\xbe", 0),
    ("pdf", b"%PDF-", 0), ("zip", b"PK\x03\x04", 0), ("zip", b"PK\x05\x06", 0),
    ("png", b"\x89PNG\r\n\x1a\n", 0), ("jpeg", b"\xff\xd8\xff", 0),
    ("gif", b"GIF87a", 0), ("gif", b"GIF89a", 0),
    ("rar", b"Rar!\x1a\x07", 0), ("7z", b"7z\xbc\xaf\x27\x1c", 0), ("gzip", b"\x1f\x8b", 0),
    ("sqlite", b"SQLite format 3\x00", 0), ("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0),
    ("riff", b"RIFF", 0), ("script", b"#!", 0),
]
SIG_LABEL = {"pe": "Executable Windows (PE)", "elf": "Executable Linux (ELF)", "macho": "Executable macOS (Mach-O)",
             "class": "Java class / Mach-O fat", "pdf": "PDF", "zip": "ZIP/Office-OOXML/APK/JAR", "png": "PNG",
             "jpeg": "JPEG", "gif": "GIF", "rar": "RAR", "7z": "7-Zip", "gzip": "GZIP", "sqlite": "SQLite",
             "ole": "Office lama (OLE)", "riff": "RIFF (WAV/AVI/WEBP)", "script": "Skrip (shebang)"}
EXEC_KINDS = {"pe", "elf", "macho", "class", "script"}
EXT_KIND = {
    ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".png": {"png"}, ".gif": {"gif"}, ".pdf": {"pdf"},
    ".zip": {"zip"}, ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"}, ".odt": {"zip"},
    ".apk": {"zip"}, ".jar": {"zip"}, ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"},
    ".rar": {"rar"}, ".7z": {"7z"}, ".gz": {"gzip"}, ".exe": {"pe"}, ".dll": {"pe"}, ".sys": {"pe"},
    ".so": {"elf"}, ".sqlite": {"sqlite"}, ".wav": {"riff"}, ".avi": {"riff"}, ".webp": {"riff"},
}
EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".msi",
            ".jar", ".so", ".dylib", ".py", ".pl", ".rb", ".o", ".out", ".bin", ".elf", ".class", ".apk", ""}
TEXTISH_EXT = {".txt", ".csv", ".log", ".json", ".xml", ".html", ".htm", ".md", ".ini", ".cfg", ".eml"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
DOUBLE_EXT = re.compile(r"\.(jpe?g|png|gif|pdf|docx?|xlsx?|pptx?|txt|zip|mp[34])\s*\.(exe|scr|bat|cmd|com|js|vbs|ps1|msi|dll|jar)$", re.I)


def sniff(head: bytes) -> Optional[str]:
    for kind, magic, off in SIGS:
        if head[off:off + len(magic)] == magic:
            return kind
    return None


def looks_text(head: bytes) -> bool:
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if not head:
        return True
    if b"\x00" in head:
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(head) > 0.90


@dataclass
class Evidence:
    path: str
    name: str
    size: int
    md5: str
    sha256: str
    mtime: str
    ctime: str
    ext: str
    sig_kind: Optional[str]
    sig_label: str
    entropy: float
    is_text: bool
    stable: bool
    acquired_at: str
    flags: list = field(default_factory=list)


def _open_readonly(path: str):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    noatime = getattr(os, "O_NOATIME", 0)   # tidak mengubah atime (Linux, bila diizinkan)
    try:
        fd = os.open(path, flags | noatime)
    except (PermissionError, OSError):
        fd = os.open(path, flags)
    return os.fdopen(fd, "rb")


def _entropy(hist: list[int], total: int) -> float:
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in hist if c)


def acquire_file(path: str, chunk: int = 1 << 20) -> Evidence:
    """Baca-saja, streaming. Berkas asli tidak pernah dibuka dengan mode tulis."""
    st1 = os.stat(path)
    md5, sha = hashlib.md5(), hashlib.sha256()
    hist, hist_total, head = [0] * 256, 0, b""
    with _open_readonly(path) as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            if not head:
                head = b[:4096]
            md5.update(b)
            sha.update(b)
            if hist_total < (1 << 20):
                for v in b[: (1 << 20) - hist_total]:
                    hist[v] += 1
                hist_total += min(len(b), (1 << 20) - hist_total)
    st2 = os.stat(path)
    iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")
    kind = sniff(head)
    p = Path(path)
    return Evidence(
        path=str(p), name=p.name, size=st2.st_size, md5=md5.hexdigest(), sha256=sha.hexdigest(),
        mtime=iso(st2.st_mtime), ctime=iso(st2.st_ctime), ext=p.suffix.lower(),
        sig_kind=kind, sig_label=SIG_LABEL.get(kind, "Tidak dikenali"),
        entropy=round(_entropy(hist, hist_total), 3), is_text=looks_text(head),
        stable=(st1.st_size, st1.st_mtime_ns) == (st2.st_size, st2.st_mtime_ns), acquired_at=utcnow())


def detect_anomalies(ev: Evidence) -> list[dict]:
    out = []
    add = lambda sev, rule, why: out.append({"severity": sev, "rule": rule, "file": ev.path, "reason": why})
    if "\u202e" in ev.name:
        add("TINGGI", "RLO", "Nama berkas memuat karakter pembalik arah (U+202E) - trik penyamaran ekstensi")
    if DOUBLE_EXT.search(ev.name):
        add("TINGGI", "DOUBLE_EXT", f"Ekstensi ganda mencurigakan: '{ev.name}'")
    exp = EXT_KIND.get(ev.ext)
    if ev.sig_kind in EXEC_KINDS and ev.ext not in EXEC_EXT:
        sev = "SEDANG" if ev.sig_kind == "script" else "TINGGI"
        add(sev, "EXEC_MASQ", f"Isi berkas adalah {ev.sig_label} tetapi berekstensi '{ev.ext}'")
    elif exp and ev.size > 0:
        if ev.sig_kind is None:
            add("SEDANG", "NO_SIG", f"Ekstensi '{ev.ext}' tidak punya signature yang sesuai (rusak/dimodifikasi)")
        elif ev.sig_kind not in exp and ev.sig_kind not in EXEC_KINDS:
            add("SEDANG", "SIG_MISMATCH", f"Ekstensi '{ev.ext}' tetapi isi berupa {ev.sig_label}")
    if ev.ext in TEXTISH_EXT and ev.entropy > 7.6 and ev.size > 1024:
        add("SEDANG", "HIGH_ENTROPY", f"Berkas '{ev.ext}' berentropi tinggi ({ev.entropy}) - kemungkinan terenkripsi/terkompresi")
    if not ev.stable:
        add("SEDANG", "UNSTABLE", "Berkas berubah selama akuisisi - hash mungkin tidak mewakili kondisi akhir")
    return out


def iter_files(paths: Iterable[str]):
    seen = set()
    for p in paths:
        p = str(p)
        if os.path.isfile(p) and not os.path.islink(p):
            rp = os.path.realpath(p)
            if rp not in seen:
                seen.add(rp)
                yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for n in sorted(files):
                    fp = os.path.join(root, n)
                    if not os.path.islink(fp):
                        rp = os.path.realpath(fp)
                        if rp not in seen:
                            seen.add(rp)
                            yield fp


# ----------------------------------------------------------------------------
# 4. Pemindai data sensitif (Bitcoin dgn validasi checksum + email)
# ----------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BTC_LEGACY = re.compile(rb"(?<![A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])")
BTC_BECH = re.compile(rb"(?<![A-Za-z0-9])(?:bc1|BC1)[A-Za-z0-9]{11,71}(?![A-Za-z0-9])")
EMAIL = re.compile(rb"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}")


def btc_base58_valid(addr: str) -> bool:
    n = 0
    for c in addr:
        n = n * 58 + _B58.index(c)
    try:
        raw = n.to_bytes(25, "big")
    except OverflowError:
        return False
    if len(addr) - len(addr.lstrip("1")) != len(raw) - len(raw.lstrip(b"\0")):
        return False
    chk = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return raw[21:] == chk and raw[0] in (0, 5)


def _polymod(values) -> int:
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def btc_bech32_valid(addr: str) -> bool:
    if addr != addr.lower() and addr != addr.upper():
        return False
    a = addr.lower()
    if len(a) not in (42, 62) or not a.startswith("bc1"):
        return False
    data = a[3:]
    if any(c not in _B32 for c in data):
        return False
    vals = [ord(x) >> 5 for x in "bc"] + [0] + [ord(x) & 31 for x in "bc"] + [_B32.index(c) for c in data]
    return _polymod(vals) in (1, 0x2bc830a3)


def btc_valid(addr: str) -> bool:
    try:
        return btc_bech32_valid(addr) if addr[:3].lower() == "bc1" else btc_base58_valid(addr)
    except ValueError:
        return False


def scan_file(path: str, max_bytes: int = 200 << 20, chunk: int = 4 << 20, overlap: int = 160) -> list[dict]:
    """Cari alamat Bitcoin (checksum valid) dan email. Mendukung UTF-8/ASCII/UTF-16."""
    found: dict[tuple, int] = {}

    def run(buf: bytes, base: int):
        for m in BTC_LEGACY.finditer(buf):
            v = m.group().decode()
            if btc_valid(v):
                found.setdefault(("bitcoin", v), base + m.start())
        for m in BTC_BECH.finditer(buf):
            v = m.group().decode()
            if btc_valid(v):
                found.setdefault(("bitcoin", v), base + m.start())
        for m in EMAIL.finditer(buf):
            found.setdefault(("email", m.group().decode().lower()), base + m.start())

    with _open_readonly(path) as f:
        first = f.read(4)
        f.seek(0)
        if first.startswith((b"\xff\xfe", b"\xfe\xff")):
            raw = f.read(max_bytes)
            run(raw.decode("utf-16", errors="ignore").encode("utf-8"), 0)
        else:
            read, tail, base = 0, b"", 0
            while read < max_bytes:
                b = f.read(chunk)
                if not b:
                    break
                read += len(b)
                run(tail + b, base - len(tail))
                tail = b[-overlap:]
                base += len(b)
    return [{"type": t, "value": v, "file": path, "offset": off} for (t, v), off in found.items()]


# ----------------------------------------------------------------------------
# 5. Intelijen visual: EXIF GPS + peta
# ----------------------------------------------------------------------------

def _to_deg(v) -> Optional[float]:
    try:
        d, m, s = (float(x) for x in v)
        return d + m / 60.0 + s / 3600.0
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_gps(path: str) -> Optional[dict]:
    try:
        from PIL import Image
        with Image.open(path) as img:
            exif = img.getexif()
            gps = exif.get_ifd(0x8825)
            if not gps or 2 not in gps or 4 not in gps:
                return None
            lat, lon = _to_deg(gps[2]), _to_deg(gps[4])
            if lat is None or lon is None:
                return None
            if str(gps.get(1, "N")).upper().startswith("S"):
                lat = -lat
            if str(gps.get(3, "E")).upper().startswith("W"):
                lon = -lon
            if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
                return None
            sub = exif.get_ifd(0x8769)
            alt = None
            with contextlib.suppress(Exception):
                alt = float(gps[6]) * (-1 if gps.get(5) == b"\x01" else 1) if 6 in gps else None
            return {"file": path, "lat": round(lat, 6), "lon": round(lon, 6), "alt": alt,
                    "taken": str(sub.get(36867) or exif.get(306) or ""),
                    "device": " ".join(str(x).strip() for x in (exif.get(271), exif.get(272)) if x)}
    except Exception:
        return None


def build_map_html(points: list[dict], title: str = "Peta Lokasi Barang Bukti") -> str:
    data = json.dumps([{"lat": p["lat"], "lon": p["lon"], "file": os.path.basename(p["file"]),
                        "taken": p.get("taken", ""), "device": p.get("device", "")} for p in points]).replace("</", "<\\/")
    rows = "".join(f"<tr><td>{html.escape(os.path.basename(p['file']))}</td><td>{p['lat']}</td><td>{p['lon']}</td>"
                   f"<td>{html.escape(p.get('taken',''))}</td><td>{html.escape(p.get('device',''))}</td></tr>" for p in points)
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>body{{font-family:system-ui,sans-serif;margin:0}}h1{{font-size:18px;padding:10px 14px;margin:0;background:#12263f;color:#fff}}
#map{{height:62vh}}#note{{padding:6px 14px;color:#a33;display:none}}table{{border-collapse:collapse;margin:10px 14px;font-size:13px}}
td,th{{border:1px solid #ccc;padding:4px 8px}}</style></head><body><h1>{html.escape(title)}</h1><div id="map"></div>
<div id="note">Peta dasar tidak dapat dimuat (offline). Gunakan tabel koordinat di bawah.</div>
<table><tr><th>Berkas</th><th>Lat</th><th>Lon</th><th>Waktu</th><th>Perangkat</th></tr>{rows}</table>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script><script>
const pts={data};
if(typeof L==='undefined'){{document.getElementById('note').style.display='block'}}else{{
const map=L.map('map');L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:19,attribution:'&copy; OpenStreetMap'}}).addTo(map);
const b=[];pts.forEach(p=>{{const d=document.createElement('div');
[p.file,p.lat+', '+p.lon,p.taken,p.device].filter(Boolean).forEach(t=>{{const r=document.createElement('div');r.textContent=t;d.appendChild(r)}});
L.marker([p.lat,p.lon]).addTo(map).bindPopup(d);b.push([p.lat,p.lon])}});
if(b.length)map.fitBounds(b,{{padding:[40,40],maxZoom:16}});else map.setView([0,115],4)}}
</script></body></html>"""


def build_kml(points: list[dict], name: str = "Barang Bukti") -> str:
    pm = "".join(f"<Placemark><name>{xesc(os.path.basename(p['file']))}</name>"
                 f"<description>{xesc(p.get('taken',''))} {xesc(p.get('device',''))}</description>"
                 f"<Point><coordinates>{p['lon']},{p['lat']},0</coordinates></Point></Placemark>" for p in points)
    return ('<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            f"<name>{xesc(name)}</name>{pm}</Document></kml>")


# ----------------------------------------------------------------------------
# 6. Pengenalan wajah: lihat face_compare.py (perbandingan 2+ foto + persentase + alasan terukur)
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# 7. Asisten AI (Gemini via REST) + ringkasan lokal sebagai fallback
# ----------------------------------------------------------------------------

DEFAULT_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")


def _mask(kind: str, v: str) -> str:
    if kind == "email":
        u, _, d = v.partition("@")
        return f"{u[:1]}***@{d}"
    return f"{v[:4]}...{v[-3:]}"


def build_digest(s: "Session", redact: bool = True) -> dict:
    """Ringkasan terstruktur yang dikirim ke AI - BUKAN isi berkas. Nilai sensitif dimasking."""
    name = (lambda p: "(disembunyikan)") if redact else os.path.basename
    wallets = [f for f in s.findings if f["type"] == "bitcoin"]
    emails = [f for f in s.findings if f["type"] == "email"]
    return {
        "perkara": {"nomor": s.case.get("nomor", ""), "nama": s.case.get("nama", "")},
        "jumlah_barang_bukti": len(s.evidences),
        "anomali": [{"tingkat": a["severity"], "aturan": a["rule"],
                     "alasan": (a["reason"].replace(os.path.basename(a["file"]), "[berkas]") if redact else a["reason"]),
                     "berkas": name(a["file"])} for a in s.anomalies][:60],
        "dompet_bitcoin": [(_mask("bitcoin", f["value"]) if redact else f["value"]) for f in wallets][:40],
        "email": [(_mask("email", f["value"]) if redact else f["value"]) for f in emails][:40],
        "domain_email_teratas": sorted({f["value"].split("@")[1] for f in emails})[:20],
        "titik_gps": [{"lat": round(g["lat"], 3 if redact else 6), "lon": round(g["lon"], 3 if redact else 6),
                       "perangkat": g.get("device", "")} for g in s.gps][:40],
        "perbandingan_wajah": [{"pasangan": f"Foto {p['a'] + 1} vs Foto {p['b'] + 1}", "persen": p["percent"],
                                "putusan": p["verdict"], "keyakinan": p["confidence"], "metode": s.face_mode}
                               for p in s.face_pairs[:20]],
        "integritas_log_audit": "utuh" if s.audit.verify()[0] else "RUSAK",
    }


def gemini_summarize(digest: dict, api_key: str, model: str = DEFAULT_GEMINI_MODEL,
                     timeout: int = 60) -> tuple[Optional[str], Optional[str]]:
    """Kembalikan (teks, error). Kunci API tidak pernah dimasukkan ke pesan error."""
    if not api_key:
        return None, "Kunci API Gemini belum diisi"
    prompt = ("Anda asisten analis forensik digital. Susun ringkasan investigasi berbahasa Indonesia formal "
              "(maks 300 kata) dengan bagian: Gambaran Umum, Temuan Utama, Prioritas Risiko, Rekomendasi "
              "Tindak Lanjut. Gunakan HANYA data JSON berikut; jangan mengarang fakta, identitas, atau "
              "kesimpulan hukum. Tandai ketidakpastian. Kecocokan wajah hanyalah indikasi yang wajib "
              "diverifikasi manusia.\n\nDATA:\n" + json.dumps(digest, ensure_ascii=False, indent=1))
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}],
                       "generationConfig": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=body, headers={"Content-Type": "application/json", "x-goog-api-key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            j = json.loads(r.read().decode())
        text = "".join(p.get("text", "") for p in j["candidates"][0]["content"]["parts"]).strip()
        return (text or None), (None if text else "Respons Gemini kosong")
    except urllib.error.HTTPError as e:
        with contextlib.suppress(Exception):
            msg = json.loads(e.read().decode()).get("error", {}).get("message", "")
            return None, f"Gemini HTTP {e.code}: {msg[:200]}"
        return None, f"Gemini HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return None, f"Tidak dapat menghubungi Gemini ({type(e).__name__}). Gunakan ringkasan lokal."
    except (KeyError, IndexError, ValueError):
        return None, "Format respons Gemini tidak dikenali"


def local_summary(s: "Session") -> str:
    high = [a for a in s.anomalies if a["severity"] == "TINGGI"]
    wal = [f for f in s.findings if f["type"] == "bitcoin"]
    em = [f for f in s.findings if f["type"] == "email"]
    L = [f"RINGKASAN OTOMATIS (lokal, non-AI) - Perkara {s.case.get('nomor') or '-'}",
         f"Total barang bukti diakuisisi: {len(s.evidences)} berkas.",
         f"Anomali: {len(s.anomalies)} (tingkat TINGGI: {len(high)})."]
    for a in high[:5]:
        L.append(f"  - {os.path.basename(a['file'])}: {a['reason']}")
    L.append(f"Alamat Bitcoin valid ditemukan: {len(wal)}; alamat email unik: {len(em)}.")
    L.append(f"Berkas foto bermetadata GPS: {len(s.gps)}.")
    if s.face_pairs:
        top = max(s.face_pairs, key=lambda p: p["percent"])
        L.append(f"Perbandingan wajah ({s.face_mode}): {len(s.face_pairs)} pasangan foto; tertinggi {fmt_pct(top['percent'])} "
                 f"(Foto {top['a'] + 1} vs Foto {top['b'] + 1}, {top['verdict']}, keyakinan {top['confidence']}) - wajib diverifikasi manusia.")
    L.append("Catatan: seluruh temuan bersifat triase awal dan harus divalidasi pemeriksa sebelum dipakai sebagai alat bukti.")
    return "\n".join(L)


# ----------------------------------------------------------------------------
# 8. Sesi investigasi (orkestrasi) + login terintegrasi audit
# ----------------------------------------------------------------------------

class Session:
    def __init__(self, home: Path, actor: str, role: str):
        self.home, self.actor, self.role = Path(home), actor, role
        self.audit = AuditLog(self.home / "audit.jsonl")
        self.case = {"nomor": "", "nama": "", "penyidik": actor, "satuan": "", "lokasi": "", "catatan": ""}
        self.evidences: list[Evidence] = []
        self.findings: list[dict] = []
        self.anomalies: list[dict] = []
        self.gps: list[dict] = []
        self.face_photos: list[dict] = []
        self.face_pairs: list[dict] = []
        self.face_mode = ""
        self.errors: list[str] = []
        self.summary = ""
        self.summary_source = ""

    def acquire_and_scan(self, paths, scan_all: bool = False,
                         progress: Optional[Callable] = None, cancelled: Optional[Callable] = None) -> int:
        files = list(iter_files(paths))
        known = {e.path for e in self.evidences}
        added = 0
        self.audit.append(self.actor, "ACQUIRE_START", {"sumber": [str(p) for p in paths], "jumlah_berkas": len(files)})
        for i, fp in enumerate(files, 1):
            if cancelled and cancelled():
                self.audit.append(self.actor, "ACQUIRE_CANCELLED", {"diproses": i - 1})
                break
            if progress:
                progress(i, len(files), fp)
            if fp in known:
                continue
            try:
                ev = acquire_file(fp)
            except OSError as e:
                self.errors.append(f"{fp}: {e.strerror or e}")
                self.audit.append(self.actor, "ACQUIRE_ERROR", {"file": fp, "error": str(e)})
                continue
            ev.flags = detect_anomalies(ev)
            self.anomalies += ev.flags
            if scan_all or ev.is_text:
                try:
                    self.findings += scan_file(fp)
                except OSError as e:
                    self.errors.append(f"scan {fp}: {e}")
            if ev.sig_kind in ("jpeg", "png", "riff") or ev.ext in IMAGE_EXT:
                g = extract_gps(fp)
                if g:
                    self.gps.append(g)
            self.evidences.append(ev)
            added += 1
            self.audit.append(self.actor, "ACQUIRE", {"file": ev.path, "size": ev.size, "md5": ev.md5,
                                                      "sha256": ev.sha256, "stable": ev.stable})
        self.audit.append(self.actor, "SCAN_DONE", {"bukti": len(self.evidences), "temuan": len(self.findings),
                                                    "anomali": len(self.anomalies), "gps": len(self.gps)})
        return added

    def reverify(self) -> list[dict]:
        """Hitung ulang hash seluruh bukti & bandingkan dengan nilai saat akuisisi."""
        res = []
        for ev in self.evidences:
            try:
                now = acquire_file(ev.path)
                ok = (now.sha256 == ev.sha256 and now.md5 == ev.md5)
            except OSError:
                ok = False
            res.append({"file": ev.path, "ok": ok})
        bad = [r for r in res if not r["ok"]]
        self.audit.append(self.actor, "REVERIFY", {"total": len(res), "berubah": len(bad)})
        return res

    def compare_faces(self, paths, model_dir: Optional[Path] = None, progress: Optional[Callable] = None,
                      cancelled: Optional[Callable] = None) -> list[dict]:
        """Bandingkan 2+ foto wajah. Tiap pasangan: persentase kemiripan + alasan terukur + citra anotasi."""
        from face_compare import FaceComparer
        uniq, seen = [], set()
        for p in paths:
            rp = os.path.realpath(str(p))
            if rp not in seen:
                seen.add(rp)
                uniq.append(str(p))
        if len(uniq) < 2:
            raise ValueError("Pilih minimal 2 foto yang berbeda untuk dibandingkan")
        if len(uniq) > MAX_PHOTOS:
            raise ValueError(f"Maksimal {MAX_PHOTOS} foto sekaligus")
        fc = FaceComparer(model_dir)
        self.face_mode = fc.label
        photos = []
        for i, p in enumerate(uniq, 1):
            if cancelled and cancelled():
                break
            if progress:
                progress(i, len(uniq), p)
            photos.append(fc.analyze(p))
        pairs = []
        for a in range(len(photos)):
            for b in range(a + 1, len(photos)):
                if cancelled and cancelled():
                    break
                if photos[a].ok and photos[b].ok:
                    pairs.append(fc.compare(photos[a], photos[b], a, b))
        in_ev = {os.path.realpath(e.path) for e in self.evidences}
        self.face_photos = [dict(ph.public(), dalam_barang_bukti=os.path.realpath(ph.path) in in_ev) for ph in photos]
        self.face_pairs = pairs
        if fc.note:
            self.errors.append(fc.note)
        self.audit.append(self.actor, "FACE_COMPARE", {
            "metode": fc.label,
            "foto": [{"nama": ph["name"], "sha256": ph["sha256"], "terbaca": ph["ok"]} for ph in self.face_photos],
            "pasangan": [{"a": p["a"] + 1, "b": p["b"] + 1, "persen": p["percent"], "keyakinan": p["confidence"]} for p in pairs]})
        return pairs

    def make_summary(self, api_key: str = "", model: str = DEFAULT_GEMINI_MODEL, redact: bool = True) -> tuple[str, Optional[str]]:
        """Coba Gemini; bila gagal otomatis jatuh ke ringkasan lokal. Return (teks, pesan_error)."""
        if api_key:
            text, err = gemini_summarize(build_digest(self, redact), api_key, model)
            self.audit.append(self.actor, "AI_SUMMARY", {"model": model, "ok": bool(text), "redact": redact})
            if text:
                self.summary, self.summary_source = text, f"Gemini ({model}) - draf, wajib ditinjau pemeriksa"
                return text, None
            self.summary, self.summary_source = local_summary(self), "Ringkasan lokal (otomatis)"
            return self.summary, err
        self.summary, self.summary_source = local_summary(self), "Ringkasan lokal (otomatis)"
        return self.summary, None

    # --- ekspor ---------------------------------------------------------
    def manifest(self) -> dict:
        return {"aplikasi": APP_NAME, "dibuat": utcnow(), "pemeriksa": self.actor, "perkara": self.case,
                "barang_bukti": [asdict(e) for e in self.evidences], "temuan": self.findings,
                "gps": self.gps, "wajah": {"metode": self.face_mode, "foto": self.face_photos,
                                           "pasangan": [{k: v for k, v in p.items() if k != "image_png"} for p in self.face_pairs]}}

    def manifest_fingerprint(self) -> str:
        rows = sorted((e.path, e.md5, e.sha256) for e in self.evidences)
        return hashlib.sha256(json.dumps(rows).encode()).hexdigest()

    def export_manifest(self, path: str) -> None:
        _write_json(Path(path), self.manifest())
        self.audit.append(self.actor, "EXPORT_MANIFEST", {"path": str(path)})

    def export_map(self, path: str) -> None:
        Path(path).write_text(build_map_html(self.gps), encoding="utf-8")
        self.audit.append(self.actor, "EXPORT_MAP", {"path": str(path), "titik": len(self.gps)})

    def export_kml(self, path: str) -> None:
        Path(path).write_text(build_kml(self.gps), encoding="utf-8")
        self.audit.append(self.actor, "EXPORT_KML", {"path": str(path)})

    def make_pdf(self, path: str) -> None:
        ok, n, bad = self.audit.verify()
        make_report_pdf(path, self, (ok, n, bad))
        self.audit.append(self.actor, "EXPORT_PDF", {"path": str(path), "fingerprint": self.manifest_fingerprint()})


def login(username: str, password: str, otp: str, home: Path = HOME) -> Session:
    store, audit = AuthStore(home), AuditLog(Path(home) / "audit.jsonl")
    try:
        role = store.authenticate(username.strip(), password, otp)
    except AuthError as e:
        audit.append(username.strip()[:32] or "?", "LOGIN_FAIL",
                     {"alasan": "akun terkunci" if "dikunci" in str(e) else "kredensial/OTP tidak valid"})
        raise
    audit.append(username.strip(), "LOGIN_OK", {"role": role})
    return Session(Path(home), username.strip(), role)


def bootstrap_admin(username: str, password: str, home: Path = HOME) -> str:
    """Setup awal: HANYA bila belum ada pengguna. Mengembalikan (OTP login pertama, kode pemulihan Admin)."""
    st = AuthStore(home)
    if st.has_users():
        raise PermissionError("Setup awal hanya untuk instalasi yang belum memiliki pengguna")
    st.add_user(username, password, "admin")
    recovery = st.set_recovery(username)
    AuditLog(Path(home) / "audit.jsonl").append(username, "BOOTSTRAP_ADMIN", {})
    return st.issue_otp(username), recovery


def request_otp(username: str, home: Path = HOME) -> tuple[str, str]:
    """Penyidik meminta OTP ke Admin. Mengembalikan (id_permintaan, kode_verifikasi)."""
    rid, vcode = OtpRequests(home).create(username)
    AuditLog(Path(home) / "audit.jsonl").append(username.strip()[:32], "OTP_REQUEST", {"rid": rid})
    return rid, vcode


def recover_admin(username: str, code: str, new_password: str, home: Path = HOME) -> tuple[str, str]:
    audit = AuditLog(Path(home) / "audit.jsonl")
    try:
        otp, new_code = AuthStore(home).recover_admin(username.strip(), code, new_password)
    except AuthError:
        audit.append(username.strip()[:32] or "?", "RECOVERY_FAIL", {})
        raise
    audit.append(username.strip(), "RECOVERY_OK", {"catatan": "sandi diganti, akun dibuka, kode pemulihan dirotasi"})
    return otp, new_code


def _csv_safe(v) -> str:
    t = str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t   # cegah CSV/formula injection


class AdminService:
    """
    Layanan dashboard Admin. Hak akses DITEGAKKAN DI SINI (bukan hanya disembunyikan di GUI):
    peran dicek ulang dari penyimpanan pada setiap operasi, jadi admin yang dinonaktifkan/diturunkan
    langsung kehilangan akses walau sesinya masih terbuka.
    """

    def __init__(self, session: "Session"):
        self.s = session
        self.store = AuthStore(session.home)
        self.reqs = OtpRequests(session.home)
        self._check()

    def _check(self) -> None:
        me = self.store.list_users().get(self.s.actor)
        if self.s.role != "admin" or not me or me["role"] != "admin" or me["disabled"]:
            raise PermissionError("Hanya Admin aktif yang dapat memakai dashboard ini")

    def _log(self, action: str, detail: dict) -> None:
        self.s.audit.append(self.s.actor, action, detail)

    def _other_active_admins(self, target: str) -> int:
        return sum(1 for u, d in self.store.list_users().items()
                   if u != target and d["role"] == "admin" and not d["disabled"])

    def users(self) -> dict:
        self._check()
        return self.store.list_users()

    def add_user(self, username: str, password: str, role: str = "penyidik") -> None:
        self._check()
        self.store.add_user(username, password, role)
        self._log("ADMIN_ADD_USER", {"user": username, "role": role})

    def reset_password(self, username: str, password: str) -> None:
        self._check()
        self.store.set_password(username, password)
        self._log("ADMIN_RESET_PASSWORD", {"user": username})

    def unlock(self, username: str) -> None:
        self._check()
        self.store.unlock(username)
        self._log("ADMIN_UNLOCK", {"user": username})

    def set_disabled(self, username: str, flag: bool) -> None:
        self._check()
        if flag and username == self.s.actor:
            raise ValueError("Tidak dapat menonaktifkan akun sendiri")
        if flag and self.store.list_users().get(username, {}).get("role") == "admin" and self._other_active_admins(username) == 0:
            raise ValueError("Tidak dapat menonaktifkan Admin aktif terakhir")
        self.store.set_disabled(username, flag)
        self._log("ADMIN_DISABLE" if flag else "ADMIN_ENABLE", {"user": username})

    def set_role(self, username: str, role: str) -> None:
        self._check()
        if role != "admin" and self.store.list_users().get(username, {}).get("role") == "admin":
            if username == self.s.actor:
                raise ValueError("Tidak dapat menurunkan peran akun sendiri")
            if self._other_active_admins(username) == 0:
                raise ValueError("Tidak dapat menurunkan Admin aktif terakhir")
        self.store.set_role(username, role)
        self._log("ADMIN_SET_ROLE", {"user": username, "role": role})

    def delete_user(self, username: str) -> None:
        self._check()
        if username == self.s.actor:
            raise ValueError("Tidak dapat menghapus akun sendiri")
        if self.store.list_users().get(username, {}).get("role") == "admin" and self._other_active_admins(username) == 0:
            raise ValueError("Tidak dapat menghapus Admin aktif terakhir")
        self.store.delete_user(username)
        self._log("ADMIN_DELETE_USER", {"user": username})

    def issue_otp(self, username: str, ttl_minutes: int = OTP_TTL // 60) -> tuple[str, float]:
        self._check()
        if not 1 <= int(ttl_minutes) <= 60:
            raise ValueError("Masa berlaku OTP 1-60 menit")
        if self.store.list_users().get(username, {}).get("disabled"):
            raise ValueError("Akun dinonaktifkan")
        code = self.store.issue_otp(username, int(ttl_minutes) * 60)
        self._log("ADMIN_ISSUE_OTP", {"user": username, "ttl_menit": int(ttl_minutes)})   # kode TIDAK dicatat
        return code, time.time() + int(ttl_minutes) * 60

    def pending_otps(self) -> list[dict]:
        self._check()
        return self.store.pending_otps()

    def otp_requests(self) -> list[dict]:
        self._check()
        users = self.store.list_users()
        out = []
        for r in self.reqs.list_pending():
            d = users.get(r["user"])
            out.append(dict(r, dikenal=bool(d) and not d["disabled"]))
        return out

    def approve_otp_request(self, rid: str, vcode: str, ttl_minutes: int = OTP_TTL // 60) -> str:
        self._check()
        if not 1 <= int(ttl_minutes) <= 60:
            raise ValueError("Masa berlaku OTP 1-60 menit")
        req = next((r for r in self.reqs.list_pending() if r["rid"] == rid), None)
        if req and req["user"] == self.s.actor:
            raise ValueError("Permintaan akun Anda sendiri harus disetujui Admin lain")
        try:
            user = self.reqs.approve(rid, vcode, self.store, int(ttl_minutes))
        except ValueError as e:
            self._log("ADMIN_APPROVE_FAIL", {"rid": rid, "alasan": str(e)[:80]})
            raise
        self._log("ADMIN_APPROVE_OTP", {"user": user, "rid": rid, "ttl_menit": int(ttl_minutes)})   # kode TIDAK dicatat
        return user

    def reject_otp_request(self, rid: str) -> bool:
        self._check()
        ok = self.reqs.reject(rid)
        if ok:
            self._log("ADMIN_REJECT_OTP", {"rid": rid})
        return ok

    def make_recovery_code(self) -> str:
        """Kode pemulihan untuk akun Admin yang sedang login. Tampil sekali; kode lama hangus."""
        self._check()
        code = self.store.set_recovery(self.s.actor)
        self._log("ADMIN_NEW_RECOVERY", {"user": self.s.actor})
        return code

    def revoke_otp(self, otp_id: str) -> bool:
        self._check()
        ok = self.store.revoke_otp(otp_id)
        if ok:
            self._log("ADMIN_REVOKE_OTP", {"id": otp_id[:8]})
        return ok

    def stats(self, hours: int = 24) -> dict:
        self._check()
        from collections import Counter
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
        c, fails, recovered = Counter(), Counter(), set()
        for e in self.s.audit.read():
            try:
                if dt.datetime.fromisoformat(e["ts"]) < since:
                    continue
            except (KeyError, ValueError):
                continue
            c[e["action"]] += 1
            if e["action"] == "LOGIN_FAIL":
                fails[e["actor"]] += 1
            if e["action"] == "RECOVERY_OK":
                recovered.add(e["actor"])
        users, now = self.store.list_users(), time.time()
        ok, n, bad = self.s.audit.verify()
        return {"hours": hours, "login_ok": c["LOGIN_OK"], "login_fail": c["LOGIN_FAIL"],
                "users": len(users), "locked": sum(1 for u in users.values() if u["locked_until"] > now),
                "disabled": sum(1 for u in users.values() if u["disabled"]),
                "otp_aktif": len(self.store.pending_otps()), "akuisisi": c["ACQUIRE"], "pdf": c["EXPORT_PDF"],
                "ai": c["AI_SUMMARY"], "chain_ok": ok, "chain_n": n, "chain_bad": bad,
                "mencurigakan": sorted(u for u, k in fails.items() if k >= 3),
                "permintaan_otp": len(self.reqs.list_pending()),
                "tanpa_pemulihan": sorted(u for u, d in users.items() if d["role"] == "admin" and not d["disabled"] and not d["has_recovery"]),
                "pemulihan_dipakai": sorted(recovered)}

    def audit_rows(self, actor: str = "", action: str = "", text: str = "", limit: int = 500) -> list[dict]:
        self._check()
        a, ac, t = (actor or "").lower(), (action or "").lower(), (text or "").lower()
        out = []
        for e in reversed(self.s.audit.read()):
            if "corrupt" in e:
                continue
            if a and a not in str(e.get("actor", "")).lower():
                continue
            if ac and ac not in str(e.get("action", "")).lower():
                continue
            if t and t not in json.dumps(e.get("detail", {}), ensure_ascii=False).lower():
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def export_audit_csv(self, path: str) -> int:
        import csv
        self._check()
        rows = self.s.audit.read()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["waktu_utc", "aktor", "aksi", "rincian", "hash_sebelumnya", "hash"])
            for e in rows:
                if "corrupt" in e:
                    continue
                w.writerow([e["ts"], _csv_safe(e["actor"]), e["action"],
                            _csv_safe(json.dumps(e["detail"], ensure_ascii=False)), e["prev"], e["hash"]])
        self._log("ADMIN_EXPORT_AUDIT", {"path": str(path), "baris": len(rows)})
        return len(rows)


# ----------------------------------------------------------------------------
# 9. Generator PDF "Berita Acara Pemeriksaan"
# ----------------------------------------------------------------------------

def make_report_pdf(path: str, s: Session, audit_status: tuple) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

    ss = getSampleStyleSheet()
    H = ParagraphStyle("H", parent=ss["Heading2"], fontSize=11, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#12263f"))
    N = ParagraphStyle("N", parent=ss["Normal"], fontSize=9, leading=12)
    C = ParagraphStyle("C", parent=N, alignment=1)
    T = ParagraphStyle("T", parent=ss["Title"], fontSize=14, leading=17, spaceAfter=2)
    M = ParagraphStyle("M", parent=N, fontName="Courier", fontSize=6.8, leading=8.2)
    S = ParagraphStyle("S", parent=N, fontSize=8, leading=10)
    import unicodedata

    def vis(t: str) -> str:   # karakter kontrol/bidi dibuat terlihat, mis. [U+202E]
        return "".join(f"[U+{ord(c):04X}]" if unicodedata.category(c) in ("Cf", "Cc") and c != "\n" else c for c in t)

    P = lambda t, st=N: Paragraph(xesc(vis(str(t))).replace("\n", "<br/>"), st)
    now = dt.datetime.now().astimezone()
    case = s.case
    story = [Paragraph("BERITA ACARA PEMERIKSAAN", T),
             Paragraph("Barang Bukti Digital - Triase Forensik", C),
             Paragraph(f"Nomor Perkara: {xesc(case.get('nomor') or '-')}", C), Spacer(1, 10)]

    info = [["Nama perkara", case.get("nama") or "-"], ["Pemeriksa / Penyidik", case.get("penyidik") or s.actor],
            ["Satuan / Instansi", case.get("satuan") or "-"], ["Lokasi pemeriksaan", case.get("lokasi") or "-"],
            ["Waktu pembuatan", now.strftime("%d-%m-%Y %H:%M:%S %Z")],
            ["Sidik manifest (SHA-256)", s.manifest_fingerprint()]]
    t = Table([[P(a, S), P(b, M if "Sidik" in a else S)] for a, b in info], colWidths=[4.2 * cm, 12.8 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Paragraph("I. DASAR PEMERIKSAAN", H),
              P("Pada tanggal tersebut di atas, pemeriksa melakukan akuisisi barang bukti digital secara baca-saja "
                "(read-only) tanpa mengubah berkas asli, menghitung nilai hash MD5 dan SHA-256 untuk setiap berkas, "
                "serta melakukan pemindaian triase atas data sensitif, anomali berkas, metadata lokasi, dan "
                "kecocokan wajah sebagaimana dirinci berikut ini."),
              Paragraph("II. DAFTAR BARANG BUKTI DAN NILAI HASH", H)]

    rows = [[P("No", S), P("Nama berkas / ukuran", S), P("Hash", S)]]
    for i, e in enumerate(s.evidences, 1):
        rows.append([P(i, S), P(f"{e.name}\n{e.size:,} byte\nJenis isi: {e.sig_label}", S),
                     Paragraph(f"MD5: {e.md5}<br/>SHA-256: {e.sha256}", M)])
    if len(rows) == 1:
        rows.append([P("-", S), P("(tidak ada barang bukti)", S), P("", S)])
    t = Table(rows, colWidths=[0.9 * cm, 6.0 * cm, 10.1 * cm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde5ef")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)

    def section(title, header, data, widths, empty):
        story.append(Paragraph(title, H))
        if not data:
            story.append(P(empty))
            return
        cap = 500
        tbl = Table([[P(h, S) for h in header]] + [[P(c, S) for c in r] for r in data[:cap]], colWidths=widths, repeatRows=1)
        tbl.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                 ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde5ef")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(tbl)
        if len(data) > cap:
            story.append(P(f"... dan {len(data) - cap} baris lain (lihat manifest JSON)."))

    bn = os.path.basename
    section("III. ANOMALI BERKAS", ["Tingkat", "Berkas", "Keterangan"],
            [[a["severity"], bn(a["file"]), a["reason"]] for a in sorted(s.anomalies, key=lambda a: a["severity"] != "TINGGI")],
            [2.0 * cm, 5.0 * cm, 10.0 * cm], "Tidak ditemukan anomali.")
    section("IV. DATA SENSITIF TERDETEKSI", ["Jenis", "Nilai", "Berkas"],
            [["Bitcoin" if f["type"] == "bitcoin" else "Email", f["value"], bn(f["file"])] for f in s.findings],
            [2.0 * cm, 9.0 * cm, 6.0 * cm], "Tidak ditemukan alamat Bitcoin valid maupun email.")
    section("V. METADATA LOKASI (EXIF GPS)", ["Berkas", "Koordinat", "Waktu / perangkat"],
            [[bn(g["file"]), f"{g['lat']}, {g['lon']}", f"{g.get('taken','')} {g.get('device','')}".strip()] for g in s.gps],
            [5.0 * cm, 4.0 * cm, 8.0 * cm], "Tidak ada foto dengan metadata GPS.")
    story.append(Paragraph("VI. PERBANDINGAN WAJAH", H))
    if not s.face_photos:
        story.append(P("Perbandingan wajah tidak dijalankan."))
    else:
        from io import BytesIO
        from PIL import Image as PILImage
        from reportlab.platypus import CondPageBreak, Image as RLImage
        H3 = ParagraphStyle("H3", parent=N, fontName="Helvetica-Bold", fontSize=9.5, spaceBefore=8, spaceAfter=3)
        story.append(P(f"Metode: {s.face_mode}. Persentase adalah skor kemiripan visual relatif, BUKAN probabilitas identitas; "
                       "hasil wajib diverifikasi oleh pemeriksa manusia.", S))
        rows = [[P("Foto", S), P("Berkas / SHA-256", S), P("Status", S)]]
        for i, ph in enumerate(s.face_photos, 1):
            st = f"Wajah terdeteksi; mata: {ph['metode_mata']}" if ph["ok"] else ph["note"]
            rows.append([P(i, S), Paragraph(xesc(vis(ph["name"])) + f"<br/><font name='Courier' size='6.5'>{ph['sha256']}</font>", S), P(st, S)])
        t = Table(rows, colWidths=[1.0 * cm, 9.0 * cm, 7.0 * cm], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde5ef")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        if not s.face_pairs:
            story.append(P("Tidak ada pasangan foto yang dapat dibandingkan (wajah tidak terdeteksi pada foto lain)."))
        for p in sorted(s.face_pairs, key=lambda r: -r["percent"])[:12]:
            story.append(CondPageBreak(9 * cm))
            story.append(Paragraph(f"Foto {p['a'] + 1} vs Foto {p['b'] + 1}: {fmt_pct(p['percent'])} - {xesc(p['verdict'])} (keyakinan {p['confidence']})", H3))
            ct = Table([[P("Komponen", S), P("Skor", S), P("Bobot", S), P("Poin", S)]] +
                       [[P(f"{c['nama']} ({c['detail']})", S), P(fmt_pct(c["skor"]), S), P(f"{int(round(c['bobot'] * 100))}%", S), P(fmt_num(c["poin"], 1), S)]
                        for c in p["components"]], colWidths=[10.0 * cm, 2.4 * cm, 2.3 * cm, 2.3 * cm])
            ct.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde5ef"))]))
            story.append(ct)
            for sec in p["alasan"]:
                story.append(Paragraph(f"<b>{xesc(sec['judul'])}</b>", ParagraphStyle("B", parent=S, spaceBefore=4)))
                for b in sec["butir"]:
                    story.append(Paragraph("&bull; " + xesc(vis(b)), ParagraphStyle("L", parent=S, leftIndent=10, firstLineIndent=-8)))
            if p.get("image_png"):
                w_, h_ = PILImage.open(BytesIO(p["image_png"])).size
                story += [Spacer(1, 4), RLImage(BytesIO(p["image_png"]), width=17 * cm, height=17 * cm * h_ / w_)]

    story.append(Paragraph("VII. RINGKASAN ANALISIS", H))
    story.append(P(s.summary or local_summary(s)))
    if s.summary_source:
        story.append(P(f"Sumber: {s.summary_source}", S))
    ok, n, bad = audit_status
    story += [Paragraph("VIII. INTEGRITAS CHAIN OF CUSTODY", H),
              P(f"Log audit berantai-hash: {n} entri - " + ("UTUH, tidak ada indikasi perubahan." if ok else f"RUSAK pada entri #{bad}. Laporan tidak boleh dipakai sebelum diselidiki."))]
    if s.errors:
        story.append(P(f"Berkas yang gagal dibaca: {len(s.errors)}. " + "; ".join(s.errors[:5]), S))

    sig = Table([[P("Pemeriksa,", N), P("Mengetahui, Komandan/Atasan,", N)], [P("\n\n\n\n", N), P("\n\n\n\n", N)],
                 [P(f"( {case.get('penyidik') or s.actor} )", N), P("( ..................................... )", N)]],
                colWidths=[8.5 * cm, 8.5 * cm])
    story += [Spacer(1, 14), KeepTogether([P("Demikian berita acara ini dibuat dengan sebenarnya.", N), Spacer(1, 6), sig])]

    def footer(c, d):
        c.saveState()
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.grey)
        c.drawString(2 * cm, 1.1 * cm, f"{APP_NAME} | Perkara {case.get('nomor') or '-'} | manifest {s.manifest_fingerprint()[:16]}")
        c.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Halaman {d.page}")
        c.restoreState()

    SimpleDocTemplate(path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                      title="Berita Acara Pemeriksaan", author=s.actor).build(story, onFirstPage=footer, onLaterPages=footer)
