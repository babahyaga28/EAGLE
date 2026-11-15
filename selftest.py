#!/usr/bin/env python3
"""selftest.py - uji otomatis headless: python selftest.py"""
import hashlib, os, shutil, sys, tempfile, time
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="ft_"))
os.environ["FORENSIC_HOME"] = str(TMP / "home")
sys.path.insert(0, str(Path(__file__).parent))
import osint_core as core  # noqa: E402

PASS = FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    PASS += bool(cond); FAIL += (not cond)
    print(f"  [{'OK' if cond else 'GAGAL'}] {name} {extra if not cond else ''}")


def make_evidence(d: Path):
    from PIL import Image
    d.mkdir(parents=True)
    (d / "sub").mkdir()
    valid_btc = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                 "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                 "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"]
    bad_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"          # checksum salah
    (d / "catatan.txt").write_text(
        "transfer ke " + valid_btc[0] + " dan " + valid_btc[1] + "\n" + valid_btc[2].upper() + "\n" + valid_btc[3] +
        f"\nfake {bad_btc}\nhubungi Pelaku.Utama@Example.com atau x@y.co.id, bukan 'abc@' atau a@b\n", encoding="utf-8")
    (d / "u16.txt").write_bytes(b"\xff\xfe" + ("kirim " + valid_btc[0] + " ke u16@mail.org").encode("utf-16-le"))
    (d / "sub" / "liburan.jpg.exe").write_bytes(b"MZ" + b"\x90" * 300)          # ekstensi ganda + PE
    (d / "foto_biasa.jpg").write_bytes(b"MZ\x90\x00" + b"\x00" * 200)           # PE menyamar jadi JPG
    (d / "dokumen.pdf").write_bytes(b"PK\x03\x04" + b"\x00" * 50)               # ZIP menyamar PDF
    (d / "rusak.png").write_bytes(b"bukan png sama sekali")
    (d / "gambar\u202egpj.exe").write_bytes(b"MZ" + b"\x00" * 20)               # RLO
    (d / "laporan.docx").write_bytes(b"PK\x03\x04" + b"\x00" * 50)              # sah
    (d / "acak.txt").write_bytes(os.urandom(20000))                              # entropi tinggi
    # foto ber-GPS (Monas, Jakarta: 6°10'31"S 106°49'38"E)
    im = Image.new("RGB", (64, 64), (200, 30, 30))
    ex = Image.Exif()
    ex[271], ex[272] = "TestMake", "TestModel"
    ex[0x8825] = {1: "S", 2: (6.0, 10.0, 31.0), 3: "E", 4: (106.0, 49.0, 38.0)}
    im.save(d / "ber_gps.jpg", exif=ex)
    Image.new("RGB", (64, 64), (10, 200, 10)).save(d / "tanpa_gps.jpg")
    return valid_btc


def main():
    ev_dir = TMP / "bukti"
    valid_btc = make_evidence(ev_dir)
    snapshot = {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in ev_dir.rglob("*") if p.is_file()}

    print("== 1. Autentikasi zero-trust ==")
    home = TMP / "home"
    st = core.AuthStore(home)
    try:
        st.add_user("budi", "pendek", "penyidik"); check("kata sandi pendek ditolak", False)
    except ValueError:
        check("kata sandi pendek ditolak", True)
    st.add_user("budi", "KataSandiKuat#1")
    st.add_user("andi", "KataSandiKuat#2")
    otp = st.issue_otp("budi")
    for args, label in [(("budi", "salah-salah", otp), "sandi salah + OTP benar ditolak"),
                        (("budi", "KataSandiKuat#1", "00000000"), "OTP salah ditolak"),
                        (("budi", "KataSandiKuat#1", "abc"), "OTP non-angka ditolak"),
                        (("tidakada", "x", otp), "user tak dikenal ditolak"),
                        (("andi", "KataSandiKuat#2", otp), "OTP milik user lain ditolak")]:
        try:
            st.authenticate(*args); check(label, False)
        except core.AuthError:
            check(label, True)
    st.unlock("budi")
    otp = st.issue_otp("budi")
    check("login sah (sandi+OTP)", st.authenticate("budi", "KataSandiKuat#1", otp) == "penyidik")
    try:
        st.authenticate("budi", "KataSandiKuat#1", otp); check("OTP tidak bisa dipakai ulang", False)
    except core.AuthError:
        check("OTP tidak bisa dipakai ulang", True)
    exp = st.issue_otp("budi", ttl=-1)
    try:
        st.authenticate("budi", "KataSandiKuat#1", exp); check("OTP kedaluwarsa ditolak", False)
    except core.AuthError:
        check("OTP kedaluwarsa ditolak", True)
    st.unlock("budi")
    for _ in range(core.MAX_FAILS):
        try: st.authenticate("budi", "salah", "12345678")
        except core.AuthError: pass
    o2 = st.issue_otp("budi")
    try:
        st.authenticate("budi", "KataSandiKuat#1", o2); check("akun terkunci setelah 5 gagal", False)
    except core.AuthError as e:
        check("akun terkunci setelah 5 gagal", "dikunci" in str(e))
    st.unlock("budi")

    print("== 2. Akuisisi, hash, pemindai, anomali, GPS ==")
    otp = st.issue_otp("budi")
    s = core.login("budi", "KataSandiKuat#1", otp, home)
    s.case.update(nomor="LP/123/X/2026", nama="Uji Coba", satuan="Unit Siber", lokasi="Lab")
    s.acquire_and_scan([str(ev_dir)])
    check("semua berkas terakuisisi", len(s.evidences) == len(snapshot), f"{len(s.evidences)} vs {len(snapshot)}")
    ok = all(e.sha256 == hashlib.sha256(Path(e.path).read_bytes()).hexdigest() and
             e.md5 == hashlib.md5(Path(e.path).read_bytes()).hexdigest() for e in s.evidences)
    check("MD5 & SHA-256 cocok dengan perhitungan independen", ok)
    after = {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in ev_dir.rglob("*") if p.is_file()}
    check("berkas asli tidak berubah (isi & mtime)", after == snapshot)
    btc = {f["value"] for f in s.findings if f["type"] == "bitcoin"}
    check("4 jenis alamat Bitcoin valid terdeteksi (P2PKH, P2SH, bech32, taproot)", all(v.lower() in {b.lower() for b in btc} for v in valid_btc), str(btc))
    check("alamat Bitcoin ber-checksum salah ditolak", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb" not in btc)
    em = {f["value"] for f in s.findings if f["type"] == "email"}
    check("email terdeteksi (termasuk UTF-16)", {"pelaku.utama@example.com", "x@y.co.id", "u16@mail.org"} <= em, str(em))
    check("email palsu tidak terdeteksi", "a@b" not in em and "abc@" not in em)
    rules = {(os.path.basename(a["file"]), a["rule"]) for a in s.anomalies}
    check("PE menyamar JPG (foto_biasa.jpg)", ("foto_biasa.jpg", "EXEC_MASQ") in rules)
    check("ekstensi ganda .jpg.exe", ("liburan.jpg.exe", "DOUBLE_EXT") in rules)
    check("ZIP menyamar PDF", ("dokumen.pdf", "SIG_MISMATCH") in rules)
    check("PNG rusak/tanpa signature", ("rusak.png", "NO_SIG") in rules)
    check("trik RLO (U+202E)", any(r == "RLO" for _, r in rules))
    check("entropi tinggi pada .txt", ("acak.txt", "HIGH_ENTROPY") in rules)
    check("docx sah TIDAK ditandai", not any(n == "laporan.docx" for n, _ in rules))
    check("jpg sah tanpa GPS TIDAK ditandai", not any(n == "tanpa_gps.jpg" for n, _ in rules))
    check("GPS hanya dari 1 foto", len(s.gps) == 1)
    g = s.gps[0]
    check("koordinat GPS benar (-6.1753, 106.8272)", abs(g["lat"] + 6.175278) < 1e-4 and abs(g["lon"] - 106.827222) < 1e-4, str(g))
    check("perangkat EXIF terbaca", "TestModel" in g["device"])
    check("reverify: tidak ada perubahan", all(r["ok"] for r in s.reverify()))
    victim = Path(s.evidences[0].path); orig = victim.read_bytes(); victim.write_bytes(orig + b"X")
    check("reverify: mendeteksi berkas yang diubah", not all(r["ok"] for r in s.reverify()))
    victim.write_bytes(orig)

    check("karakter pembalik ditampilkan eksplisit di GUI ([U+202E])", core.visible("gambar\u202egpj.exe") == "gambar[U+202E]gpj.exe" and core.visible("a\nb") == "a\nb")
    print("== 3. Peta & ekspor ==")
    html = core.build_map_html(s.gps); kml = core.build_kml(s.gps)
    check("peta HTML memuat koordinat & Leaflet", "-6.175278" in html and "106.827222" in html and "leaflet" in html)
    evil = [{"file": "<script>alert(1)</script>.jpg", "lat": 1, "lon": 2, "taken": "", "device": ""}]
    check("peta HTML aman dari injeksi nama berkas", "<script>alert(1)" not in core.build_map_html(evil))
    check("KML valid-bentuk", kml.startswith("<?xml") and "<Placemark>" in kml)

    print("== 4. Pengenalan wajah (perbandingan foto, persentase, alasan) ==")
    import json as _j
    import numpy as np, cv2
    import face_compare as fcm
    fix = None
    try:
        import matplotlib, skimage
        gp = Path(matplotlib.__file__).parent / "mpl-data/sample_data/grace_hopper.jpg"
        ep = Path(skimage.__file__).parent / "data/astronaut.png"
        fix = (gp, ep) if gp.exists() and ep.exists() else None
    except ImportError:
        pass
    check("(prasyarat) dua foto wajah nyata dari orang berbeda tersedia untuk uji", fix is not None)

    class Scripted(fcm.FaceComparer):
        """Detektor terskrip: koordinat wajah/mata hasil pengukuran Haar pada foto nyata (OpenCV 4.13).
        Menguji seluruh pipeline (penyelarasan, skor, alasan, citra) tanpa bergantung versi OpenCV."""
        detector_available = True
        def _boxes(self, gray):
            return {(600, 512): [(149, 102, 229, 229)], (512, 512): [(178, 69, 92, 92)], (210, 179): [(52, 36, 80, 80)]}.get(gray.shape, [])
        def _eyes(self, gray, box):
            x, y, w, h = box
            l, r, m = {(600, 512): ((0.33, 0.38), (0.67, 0.37), "terdeteksi"), (512, 512): ((0.25, 0.35), (0.75, 0.37), "terdeteksi")}.get(
                gray.shape, ((0.30, 0.38), (0.70, 0.38), "diperkirakan dari proporsi wajah"))
            return (x + l[0] * w, y + l[1] * h), (x + r[0] * w, y + r[1] * h), m

    if fix:
        fd = TMP / "wajah"; fd.mkdir()
        G, E = cv2.imread(str(fix[0])), cv2.imread(str(fix[1]))
        def w(name, img, q=None):
            cv2.imwrite(str(fd / name), img, [cv2.IMWRITE_JPEG_QUALITY, q] if q else [])
            return str(fd / name)
        P = {"G": w("g.png", G), "G_copy": w("g_copy.png", G),
             "G_gamma": w("g_gamma.png", np.clip(255 * (G / 255.0) ** 1.6, 0, 255).astype(np.uint8)),
             "G_jpeg": w("g_jpeg.jpg", G, 20), "G_blur": w("g_blur.png", cv2.GaussianBlur(G, (0, 0), 2.2)),
             "G_small": w("g_small.png", cv2.resize(G, None, fx=0.35, fy=0.35, interpolation=cv2.INTER_AREA)),
             "E": w("e.png", E), "E_jpeg": w("e_jpeg.jpg", E, 20), "E_blur": w("e_blur.png", cv2.GaussianBlur(E, (0, 0), 2.2)),
             "kosong": w("kosong.png", np.full((300, 300, 3), 127, np.uint8))}
        real_cls = fcm.FaceComparer
        fcm.FaceComparer = Scripted
        try:
            names = ["G", "G_copy", "G_gamma", "G_jpeg", "G_blur", "E", "E_jpeg"]
            pairs = s.compare_faces([P[n] for n in names])
            idx = {n: i for i, n in enumerate(names)}
            pct = lambda a, b: next(p for p in pairs if {p["a"], p["b"]} == {idx[a], idx[b]})
            check("7 foto -> 21 pasangan", len(pairs) == 21)
            check("berkas identik dikenali (hash sama) & skor ~100%", pct("G", "G_copy")["identical_files"] and pct("G", "G_copy")["percent"] >= 99)
            same = [pct("G", "G_gamma"), pct("G", "G_jpeg"), pct("G", "G_blur"), pct("E", "E_jpeg")]
            diff = [pct(a, b) for a in ("G", "G_gamma", "G_jpeg", "G_blur") for b in ("E", "E_jpeg")]
            check("orang SAMA beda kondisi foto: semua >= 75%", all(p["percent"] >= 75 for p in same), str([p["percent"] for p in same]))
            check("orang BERBEDA: semua <= 40% & putusan 'Tidak mirip'", all(p["percent"] <= 40 and p["verdict"] == "Tidak mirip" for p in diff), str([p["percent"] for p in diff]))
            check("pemisahan: skor terendah orang sama > tertinggi orang berbeda + 30", min(p["percent"] for p in same) > max(p["percent"] for p in diff) + 30)
            check("persentase = jumlah poin komponen; bobot berjumlah 100%", all(abs(sum(c["poin"] for c in p["components"]) - p["percent"]) <= 0.15 and abs(sum(c["bobot"] for c in p["components"]) - 1) < 1e-9 for p in pairs))
            p0 = pct("G", "E")
            titles = [x["judul"] for x in p0["alasan"]]
            check("alasan lengkap (8 bagian termasuk skor semua wilayah & cara hitung)", len(titles) == 8 and "Cara nilai dihitung" in titles and "Skor semua wilayah wajah" in titles)
            txt = fcm.format_pair_text(p0, s.face_photos)
            check("teks alasan menyebut persentase & semua wilayah wajah", core.fmt_pct(p0["percent"]) in txt and all(n in txt for n in ("Dahi", "Hidung", "Mulut", "Dagu")))
            check("alasan memuat angka terukur (korelasi/arah tepi/tekstur)", "korelasi" in txt.lower() and "tekstur" in txt)
            check("6 wilayah, masing-masing 3 ukuran", len(p0["regions"]) == 6 and all({"korelasi", "arah_tepi", "tekstur", "skor"} <= set(r) for r in p0["regions"]))
            check("citra anotasi PNG valid", p0["image_png"][:8] == b"\x89PNG\r\n\x1a\n" and cv2.imdecode(np.frombuffer(p0["image_png"], np.uint8), 1).shape[1] >= 800)
            bp = s.compare_faces([P["G"], P["E_blur"]])[0]
            check("foto buram dilaporkan sebagai penurun keyakinan (hasil pengukuran)", "buram" in fcm.format_pair_text(bp, s.face_photos) and bp["confidence"] in ("Sedang", "Rendah"))
            sm = s.compare_faces([P["G"], P["G_small"]])[0]
            check("wajah kecil/mata tak terdeteksi -> keyakinan Rendah & alasan jujur", sm["confidence"] == "Rendah" and "diperkirakan" in fcm.format_pair_text(sm, s.face_photos))
            mixed = s.compare_faces([P["G"], P["kosong"], P["E"]])
            bad = [ph for ph in s.face_photos if not ph["ok"]]
            check("foto tanpa wajah ditandai & tidak ikut dipasangkan", len(mixed) == 1 and len(bad) == 1 and "Tidak ada wajah" in bad[0]["note"])
            for args, label in (([P["G"]], "1 foto"), ([P["G"], P["G"]], "foto yang sama dua kali"), ([P["G"]] + [str(fd / f"x{i}.png") for i in range(11)], ">10 foto")):
                try: s.compare_faces(args); check(f"ditolak: {label}", False)
                except ValueError: check(f"ditolak: {label}", True)
            miss = s.compare_faces([P["G"], str(fd / "tidak_ada.png")])
            check("berkas tak ada ditangani tanpa crash", miss == [] and not s.face_photos[1]["ok"])
            s.compare_faces([P["G"], P["G_gamma"], P["E"]])
        finally:
            fcm.FaceComparer = real_cls
        check("hash SHA-256 foto dicatat di audit (chain of custody)", any(e["action"] == "FACE_COMPARE" and len(e["detail"]["foto"][0]["sha256"]) == 64 for e in s.audit.read()))
        man = _j.dumps(s.manifest(), default=str)
        check("manifest JSON dapat diserialisasi tanpa bytes citra / tipe numpy", "image_png" not in man and bool(_j.dumps(s.face_photos)))
        dg = core.build_digest(s, redact=True)
        check("digest AI: perbandingan wajah tanpa nama berkas", dg["perbandingan_wajah"] and "g_gamma" not in str(dg))
        check("ringkasan lokal menyebut perbandingan wajah", "Perbandingan wajah" in core.local_summary(s))
        # deteksi langsung (hanya bila detektor tersedia: OpenCV 4.x) atau pesan jelas (OpenCV 5)
        live = fcm.FaceComparer()
        if live.detector_available:
            lp = s.compare_faces([P["G"], P["G_gamma"], P["E"]])
            sm_, df_ = [p for p in lp if {p["a"], p["b"]} == {0, 1}][0], [p for p in lp if {p["a"], p["b"]} == {0, 2}][0]
            check("[deteksi langsung] orang sama > orang berbeda + 30", sm_["percent"] > df_["percent"] + 30, f"{sm_['percent']} vs {df_['percent']}")
        else:
            r_ = s.compare_faces([P["G"], P["E"]])
            check("[OpenCV tanpa Haar] pesan jelas, tanpa crash", r_ == [] and all("OpenCV" in ph["note"] for ph in s.face_photos))
        s.compare_faces  # (pairs terakhir dipakai PDF di bawah)
        fcm.FaceComparer = Scripted
        try: s.compare_faces([P["G"], P["G_gamma"], P["E"]])
        finally: fcm.FaceComparer = real_cls

    print("== 5. AI Gemini & ringkasan ==")
    d = core.build_digest(s, redact=True)
    blob = str(d)
    check("digest AI tidak membocorkan alamat dompet/email utuh", valid_btc[0] not in blob and "pelaku.utama@example.com" not in blob)
    check("digest AI menyembunyikan nama berkas", "liburan" not in blob)
    text, err = core.gemini_summarize(d, "")
    check("tanpa API key -> error jelas", text is None and "API" in err)
    text, err = core.gemini_summarize(d, "KUNCI-RAHASIA-123", timeout=3)
    check("tanpa jaringan -> error aman & kunci tak bocor", text is None and err and "KUNCI-RAHASIA" not in err, str(err))
    txt, e2 = s.make_summary("KUNCI-RAHASIA-123")
    check("fallback otomatis ke ringkasan lokal", "RINGKASAN OTOMATIS" in txt and e2)

    print("== 6. PDF Berita Acara ==")
    pdf = TMP / "bap.pdf"; s.make_pdf(str(pdf))
    data = pdf.read_bytes()
    check("PDF terbentuk", data.startswith(b"%PDF") and len(data) > 3000)
    check("PDF memuat citra anotasi perbandingan wajah", b"/Image" in data and len(data) > 60000)
    try:
        from pypdf import PdfReader
        t = "".join(p.extract_text() for p in PdfReader(str(pdf)).pages)
        check("PDF memuat judul, hash, nomor perkara", "BERITA ACARA PEMERIKSAAN" in t and s.evidences[0].sha256[:20] in t.replace("\n", "") and "LP/123/X/2026" in t)
        check("PDF memuat status integritas log", "UTUH" in t)
    except ImportError:
        print("  (pypdf tidak ada, isi PDF tidak diperiksa)")
    s.export_manifest(str(TMP / "m.json")); s.export_map(str(TMP / "m.html")); s.export_kml(str(TMP / "m.kml"))
    check("ekspor manifest/peta/KML", all((TMP / n).exists() for n in ("m.json", "m.html", "m.kml")))

    print("== 7. Chain of Custody ==")
    ok, n, bad = s.audit.verify()
    check(f"log audit utuh ({n} entri)", ok and n > 10)
    lines = s.audit.path.read_text().splitlines()
    lines[3] = lines[3].replace("LOGIN", "LOGON") if "LOGIN" in lines[3] else lines[3].replace('"actor": "', '"actor": "x')
    s.audit.path.write_text("\n".join(lines) + "\n")
    ok2, _, bad2 = s.audit.verify()
    check("modifikasi log terdeteksi", (not ok2) and bad2 == 3, f"bad={bad2}")

    print("== 9. Dashboard Admin ==")
    PW = "KataSandiKuat#9"
    boot_home = TMP / "boot"
    code, rec0 = core.bootstrap_admin("komandan", PW, boot_home)
    check("bootstrap admin pertama menghasilkan OTP + kode pemulihan", len(code) == 8 and len(rec0.replace("-", "")) == 20)
    try:
        core.bootstrap_admin("penyusup", PW, boot_home); check("bootstrap ditolak jika sudah ada pengguna", False)
    except PermissionError:
        check("bootstrap ditolak jika sudah ada pengguna", True)
    adm = core.login("komandan", PW, code, boot_home)
    check("admin login", adm.role == "admin")
    svc = core.AdminService(adm)
    svc.add_user("rina", PW); svc.add_user("joko", PW)
    try:
        svc.add_user("rina", PW); check("username duplikat ditolak (tak menimpa akun)", False)
    except ValueError:
        check("username duplikat ditolak (tak menimpa akun)", True)
    # non-admin tidak boleh
    o = svc.issue_otp("rina", 5)[0]
    rina = core.login("rina", PW, o, boot_home)
    try:
        core.AdminService(rina); check("penyidik DITOLAK memakai AdminService", False)
    except PermissionError:
        check("penyidik DITOLAK memakai AdminService", True)
    # kode OTP tidak tersimpan/terbaca
    pool_txt = (boot_home / "otp_pool.json").read_text()
    code2, exp = svc.issue_otp("joko", 10)
    pool_txt = (boot_home / "otp_pool.json").read_text(); log_txt = adm.audit.path.read_text()
    check("kode OTP tidak ada di pool maupun log audit", code2 not in pool_txt and code2 not in log_txt)
    pend = svc.pending_otps()
    check("OTP aktif terdaftar tanpa kode", any(p["user"] == "joko" for p in pend) and all("h" not in p and "code" not in p for p in pend))
    check("OTP dapat dicabut -> tak bisa dipakai", svc.revoke_otp([p for p in pend if p["user"] == "joko"][0]["id"]))
    try:
        core.login("joko", PW, code2, boot_home); check("OTP yang dicabut ditolak", False)
    except core.AuthError:
        check("OTP yang dicabut ditolak", True)
    # reset sandi mencabut OTP lama
    o3 = svc.issue_otp("joko", 10)[0]
    svc.reset_password("joko", "SandiBaruKuat#7")
    try:
        core.login("joko", "SandiBaruKuat#7", o3, boot_home); check("reset sandi mencabut OTP lama", False)
    except core.AuthError:
        check("reset sandi mencabut OTP lama", True)
    check("login dengan sandi baru", core.login("joko", "SandiBaruKuat#7", svc.issue_otp("joko")[0], boot_home).actor == "joko")
    # nonaktif
    svc.set_disabled("joko", True)
    try:
        svc.issue_otp("joko"); check("tak bisa terbitkan OTP utk akun nonaktif", False)
    except ValueError:
        check("tak bisa terbitkan OTP utk akun nonaktif", True)
    svc.set_disabled("joko", False)
    svc.set_disabled("rina", True)
    try:
        core.login("rina", PW, boot_home and core.AuthStore(boot_home).issue_otp("rina"), boot_home); check("akun nonaktif tak bisa login", False)
    except core.AuthError:
        check("akun nonaktif tak bisa login", True)
    svc.set_disabled("rina", False)
    # pengaman admin terakhir / diri sendiri
    for fn, label in [(lambda: svc.delete_user("komandan"), "hapus diri sendiri"), (lambda: svc.set_disabled("komandan", True), "nonaktifkan diri sendiri"),
                      (lambda: svc.set_role("komandan", "penyidik"), "turunkan diri sendiri")]:
        try:
            fn(); check(f"ditolak: {label}", False)
        except ValueError:
            check(f"ditolak: {label}", True)
    svc.set_role("joko", "admin")
    svc.set_disabled("joko", True)       # boleh: masih ada admin aktif lain (komandan)
    check("admin kedua boleh dinonaktifkan selagi ada admin aktif lain", True)
    svc.set_disabled("joko", False)
    # hak akses dicek ulang tiap operasi: admin yang diturunkan kehilangan akses
    adm2_code = svc.issue_otp("joko")[0]
    adm2 = core.login("joko", "SandiBaruKuat#7", adm2_code, boot_home)
    svc2 = core.AdminService(adm2)
    svc.set_role("joko", "penyidik")
    try:
        svc2.users(); check("admin yang diturunkan langsung kehilangan akses (sesi lama)", False)
    except PermissionError:
        check("admin yang diturunkan langsung kehilangan akses (sesi lama)", True)
    # statistik & log
    for _ in range(3):
        try: core.login("rina", "salah-salah", "00000000", boot_home)
        except core.AuthError: pass
    st_ = svc.stats(24)
    check("statistik: login gagal terhitung", st_["login_fail"] >= 3 and st_["login_ok"] >= 3)
    check("statistik: akun mencurigakan (>=3 gagal) terdeteksi", "rina" in st_["mencurigakan"])
    check("statistik: rantai log utuh", st_["chain_ok"])
    check("filter log per aksi", all(r["action"] == "LOGIN_FAIL" for r in svc.audit_rows(action="LOGIN_FAIL")) and svc.audit_rows(action="LOGIN_FAIL"))
    # CSV injection
    try: core.login("=HYPERLINK(\"http://x\")", "x", "00000000", boot_home)
    except core.AuthError: pass
    csvp = TMP / "audit.csv"; n = svc.export_audit_csv(str(csvp))
    txt = csvp.read_text()
    check("ekspor CSV audit", n > 10 and "waktu_utc" in txt)
    check("CSV aman dari formula injection", ",=HYPERLINK" not in txt and "'=HYPERLINK" in txt)
    svc.delete_user("joko")
    check("hapus pengguna", "joko" not in svc.users())

    print("== 10. Permintaan OTP (persetujuan Admin) ==")
    import json as _json
    R = core.OtpRequests(boot_home)
    svc.add_user("sinta", PW)
    rid, vcode = core.request_otp("sinta", boot_home)
    check("permintaan menghasilkan id & kode verifikasi 6 digit", len(rid) == 8 and len(vcode) == 6 and vcode.isdigit())
    check("kode verifikasi tidak tersimpan di berkas", vcode not in (boot_home / "otp_requests.json").read_text())
    check("poll: menunggu persetujuan", R.poll(rid, vcode)["status"] == "menunggu")
    try:
        core.request_otp("sinta", boot_home); check("permintaan beruntun dibatasi (rate-limit)", False)
    except ValueError:
        check("permintaan beruntun dibatasi (rate-limit)", True)
    check("permintaan tampil di dashboard Admin", any(r["rid"] == rid and r["user"] == "sinta" and r["dikenal"] for r in svc.otp_requests()))
    wrong = f"{(int(vcode) + 1) % 10**6:06d}"
    for i in range(2):
        try: svc.approve_otp_request(rid, wrong); check("kode verifikasi salah ditolak", False)
        except ValueError as e: check(f"kode verifikasi salah ditolak (percobaan {i+1})", "tidak cocok" in str(e))
    ok_user = svc.approve_otp_request(rid, " " + vcode[:3] + " " + vcode[3:])
    check("persetujuan dengan kode benar (spasi diabaikan)", ok_user == "sinta")
    raw = (boot_home / "otp_requests.json").read_text()
    res = R.poll(rid, "000000" if vcode != "000000" else "111111")
    check("peminta dengan kode verifikasi SALAH tidak bisa membuka OTP", res["status"] == "tidak_cocok" and "otp" not in res)
    res = R.poll(rid, vcode)
    otp_ok = res.get("otp", "")
    check("peminta dengan kode benar menerima OTP 8 digit", res["status"] == "disetujui" and len(otp_ok) == 8 and otp_ok.isdigit())
    check("OTP tidak tersimpan sebagai teks biasa (berkas, pool, audit)", all(otp_ok not in x for x in (raw, (boot_home / "otp_pool.json").read_text(), adm.audit.path.read_text())))
    check("OTP hasil persetujuan dapat dipakai login", core.login("sinta", PW, otp_ok, boot_home).actor == "sinta")
    check("baca-sekali: poll kedua tidak mengembalikan OTP", R.poll(rid, vcode)["status"] == "kedaluwarsa")
    # tiga kali salah -> ditolak otomatis
    time.sleep(0)  # (rate-limit memakai created lama? atur manual di bawah)
    f = boot_home / "otp_requests.json"
    def age_requests():
        rows = _json.loads(f.read_text()) if f.exists() else []
        for r in rows: r["created"] -= 100
        f.write_text(_json.dumps(rows))
    age_requests()
    rid2, v2 = core.request_otp("sinta", boot_home)
    bad2 = f"{(int(v2) + 7) % 10**6:06d}"
    for _ in range(3):
        try: svc.approve_otp_request(rid2, bad2)
        except ValueError: pass
    check("3x salah -> permintaan ditolak otomatis", R.poll(rid2, v2)["status"] == "ditolak")
    # tolak manual
    age_requests(); rid3, v3 = core.request_otp("sinta", boot_home)
    check("Admin dapat menolak permintaan", svc.reject_otp_request(rid3) and R.poll(rid3, v3)["status"] == "ditolak")
    # pengguna tak dikenal: tidak bocor, tidak bisa disetujui
    ridx, vx = core.request_otp("hantu", boot_home)
    check("permintaan username tak dikenal tidak error (tidak membocorkan keberadaan akun)", len(ridx) == 8)
    check("... tetapi ditandai TIDAK DIKENAL di dashboard", any(r["rid"] == ridx and not r["dikenal"] for r in svc.otp_requests()))
    try: svc.approve_otp_request(ridx, vx); check("permintaan akun tak dikenal tak bisa disetujui", False)
    except ValueError: check("permintaan akun tak dikenal tak bisa disetujui", True)
    # admin tidak boleh menyetujui permintaannya sendiri
    ridk, vk = core.request_otp("komandan", boot_home)
    try: svc.approve_otp_request(ridk, vk); check("Admin tak bisa menyetujui permintaannya sendiri", False)
    except ValueError: check("Admin tak bisa menyetujui permintaannya sendiri", True)
    # kedaluwarsa
    rows = _json.loads(f.read_text())
    for r in rows: r["exp"] = time.time() - 1
    f.write_text(_json.dumps(rows))
    check("permintaan kedaluwarsa hilang dari antrean", svc.otp_requests() == [])
    # penyidik tak bisa menyetujui
    try: core.AdminService(core.login("sinta", PW, svc.issue_otp("sinta")[0], boot_home)); check("penyidik tak bisa menyetujui permintaan", False)
    except PermissionError: check("penyidik tak bisa menyetujui permintaan", True)
    st2 = svc.stats(24)
    check("statistik memuat jumlah permintaan menunggu", "permintaan_otp" in st2)
    check("log memuat OTP_REQUEST & ADMIN_APPROVE_OTP", {"OTP_REQUEST", "ADMIN_APPROVE_OTP", "ADMIN_APPROVE_FAIL"} <= {e["action"] for e in adm.audit.read()})

    print("== 11. Kode pemulihan Admin ==")
    rh = TMP / "rec"
    otp0, rec = core.bootstrap_admin("pimpinan", PW, rh)
    check("format kode pemulihan XXXX-XXXX-XXXX-XXXX-XXXX", bool(__import__("re").fullmatch(r"([A-Z2-9]{4}-){4}[A-Z2-9]{4}", rec)))
    check("kode pemulihan tidak tersimpan sebagai teks biasa", rec.replace("-", "") not in (rh / "users.json").read_text())
    a0 = core.login("pimpinan", PW, otp0, rh)
    sv = core.AdminService(a0)
    check("has_recovery tercatat", sv.users()["pimpinan"]["has_recovery"] and not sv.stats()["tanpa_pemulihan"])
    sv.add_user("admin2", PW, "admin")
    check("admin baru tanpa kode pemulihan terdeteksi di statistik", sv.stats()["tanpa_pemulihan"] == ["admin2"])
    c2 = sv.store.set_recovery("admin2"); check("set_recovery untuk admin lain", len(c2) == 24)
    try: sv.store.set_recovery("tidakada"); check("pemulihan utk akun tak ada ditolak", False)
    except ValueError: check("pemulihan utk akun tak ada ditolak", True)
    sv.add_user("biasa", PW)
    try: sv.store.set_recovery("biasa"); check("penyidik tak boleh punya kode pemulihan", False)
    except ValueError: check("penyidik tak boleh punya kode pemulihan", True)
    # kunci akun lalu pulihkan
    for _ in range(core.MAX_FAILS):
        try: core.AuthStore(rh).authenticate("pimpinan", "salah", "00000000")
        except core.AuthError: pass
    try: core.login("pimpinan", PW, core.AuthStore(rh).issue_otp("pimpinan"), rh); locked = False
    except core.AuthError as e: locked = "dikunci" in str(e)
    check("(prasyarat) akun Admin terkunci", locked)
    for bad in (rec.replace("A", "B", 1) if "A" in rec else rec[:-1] + ("2" if rec[-1] != "2" else "3"),):
        try: core.recover_admin("pimpinan", bad, "SandiPulih#12345", rh); check("kode pemulihan salah ditolak", False)
        except core.AuthError: check("kode pemulihan salah ditolak", True)
    try: core.recover_admin("pimpinan", rec, "pendek", rh); check("sandi baru pendek ditolak", False)
    except ValueError: check("sandi baru pendek ditolak", True)
    otp_r, rec_new = core.recover_admin("pimpinan", rec.lower().replace("-", " "), "SandiPulih#12345", rh)
    check("pemulihan berhasil (huruf kecil/spasi ditoleransi)", len(otp_r) == 8 and rec_new != rec)
    check("login dengan sandi baru + OTP pemulihan (akun terbuka)", core.login("pimpinan", "SandiPulih#12345", otp_r, rh).role == "admin")
    try: core.login("pimpinan", PW, core.AuthStore(rh).issue_otp("pimpinan"), rh); check("sandi lama tidak berlaku", False)
    except core.AuthError: check("sandi lama tidak berlaku", True)
    try: core.recover_admin("pimpinan", rec, "SandiLain#123456", rh); check("kode pemulihan LAMA hangus (rotasi)", False)
    except core.AuthError: check("kode pemulihan LAMA hangus (rotasi)", True)
    for who, label in (("biasa", "penyidik"), ("tidakada", "akun tak ada")):
        try: core.recover_admin(who, rec_new, "SandiLain#123456", rh); check(f"pemulihan ditolak untuk {label}", False)
        except core.AuthError: check(f"pemulihan ditolak untuk {label}", True)
    # brute force -> terkunci walau kode benar
    for _ in range(core.MAX_FAILS):
        try: core.recover_admin("pimpinan", "AAAA-AAAA-AAAA-AAAA-AAAA", "SandiLain#123456", rh)
        except core.AuthError: pass
    try: core.recover_admin("pimpinan", rec_new, "SandiLain#123456", rh); check("brute-force kode pemulihan -> terkunci 15 menit", False)
    except core.AuthError: check("brute-force kode pemulihan -> terkunci 15 menit", True)
    # admin nonaktif tidak bisa dipulihkan
    sv2 = core.AdminService(core.login("admin2", PW, sv.store.issue_otp("admin2"), rh))
    sv.set_disabled("admin2", True)
    try: core.recover_admin("admin2", c2, "SandiLain#123456", rh); check("Admin yang sengaja dinonaktifkan tak bisa dipulihkan", False)
    except core.AuthError: check("Admin yang sengaja dinonaktifkan tak bisa dipulihkan", True)
    sv.set_disabled("admin2", False)
    # menurunkan peran mencabut kode pemulihan
    sv.set_role("admin2", "penyidik")
    check("menurunkan peran mencabut kode pemulihan", not sv.users()["admin2"]["has_recovery"])
    acts = [e["action"] for e in a0.audit.read()]
    check("RECOVERY_OK & RECOVERY_FAIL tercatat", "RECOVERY_OK" in acts and "RECOVERY_FAIL" in acts)
    check("statistik menandai pemakaian pemulihan", "pimpinan" in core.AdminService(core.login("pimpinan", "SandiPulih#12345", core.AuthStore(rh).issue_otp("pimpinan"), rh)).stats()["pemulihan_dipakai"])

    print("== 8. Konsol admin ==")
    import admin_console
    check("admin list", admin_console.main(["--home", str(home), "list"]) == 0)

    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\nHasil: {PASS} lulus, {FAIL} gagal")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
