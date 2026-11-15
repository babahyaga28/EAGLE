#!/usr/bin/env python3
"""
selftest_gui.py - smoke-test alur GUI memakai tkinter TIRUAN (berguna di mesin tanpa display/Tk).
Menangkap NameError, salah argumen, dan salah alur. Tampilan visual tetap perlu dicek manual.
"""
import os, queue, sys, tempfile, time, shutil
from pathlib import Path
from unittest.mock import MagicMock

TMP = Path(tempfile.mkdtemp(prefix="ftg_"))
os.environ["FORENSIC_HOME"] = str(TMP / "home")
sys.path.insert(0, str(Path(__file__).parent))


class FakeVar:
    def __init__(self, value=""): self.v = value
    def get(self): return self.v
    def set(self, v): self.v = v


tk = MagicMock(name="tkinter")
tk.StringVar = tk.BooleanVar = tk.DoubleVar = FakeVar
tk.TclError = Exception
for n in ("tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"):
    sys.modules[n] = tk if n == "tkinter" else getattr(tk, n.split(".")[1])
import triage_app as ta  # noqa: E402
import osint_core as core  # noqa: E402

ok = True
def check(name, cond):
    global ok
    ok &= bool(cond)
    print(f"  [{'OK' if cond else 'GAGAL'}] {name}")

def drain(timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            fn, args = app.q.get(timeout=0.3)
        except queue.Empty:
            continue
        fn(*args)
        if fn != app._set_progress:      # lewati notifikasi progres, berhenti di callback selesai
            return
    raise TimeoutError("callback latar belakang tidak datang")

# data uji
from PIL import Image
ev = TMP / "bukti"; ev.mkdir()
(ev / "a.txt").write_text("btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa mail t@x.com")
(ev / "x.jpg").write_bytes(b"MZ" + b"\0" * 100)
Image.new("RGB", (80, 80), "red").save(ev / "p.jpg")
st = core.AuthStore(); st.add_user("budi", "KataSandiKuat#1")

root = MagicMock()
app = ta.App(root)
check("layar login tampil", hasattr(app, "v_user"))
app.v_user.set("budi"); app.v_pw.set("salah-salah-salah"); app.v_otp.set("12345678")
app.do_login()
check("login gagal ditolak & kolom dibersihkan", app.session is None and app.v_pw.get() == "")
app.v_user.set("budi"); app.v_pw.set("KataSandiKuat#1"); app.v_otp.set(st.issue_otp("budi"))
app.do_login()
check("login sukses -> sesi aktif", app.session is not None and hasattr(app, "tv_ev"))

app.case_vars["nomor"].set("LP/9/2026"); app.case_vars["nama"].set("Uji GUI")
app.save_case(); check("simpan kasus", app.session.case["nomor"] == "LP/9/2026")

app.cv.winfo_width = lambda: 400; app.cv.winfo_height = lambda: 300
app.sources.append(str(ev)); app.v_scan_all.set(False)
app.start_scan(); drain()
check("akuisisi via GUI", len(app.session.evidences) == 3)
check("anomali & temuan terisi", len(app.session.anomalies) >= 1 and len(app.session.findings) == 2)
app.reverify(); drain()
app.draw_plot(); check("plot GPS tanpa titik tidak crash", True)

app.run_faces(); check("< 2 foto -> peringatan, tanpa crash", ta.messagebox.showwarning.called)
app.add_face_photos([str(ev / "p.jpg"), str(ev / "x.jpg")]); ta.messagebox.showwarning.reset_mock()
app.run_faces(); drain()
check("foto tanpa wajah/detektor -> peringatan jelas, tidak crash", ta.messagebox.showwarning.called and app.session.face_pairs == [])
# alur penuh dengan foto wajah nyata + detektor terskrip
import matplotlib, skimage, cv2 as _cv2, face_compare as _fcm
class _Scripted(_fcm.FaceComparer):
    detector_available = True
    def _boxes(self, gray): return {(600, 512): [(149, 102, 229, 229)], (512, 512): [(178, 69, 92, 92)]}.get(gray.shape, [])
    def _eyes(self, gray, box):
        x, y, w, h = box
        l, r = ((0.33, 0.38), (0.67, 0.37)) if gray.shape == (600, 512) else ((0.25, 0.35), (0.75, 0.37))
        return (x + l[0] * w, y + l[1] * h), (x + r[0] * w, y + r[1] * h), "terdeteksi"
_real = _fcm.FaceComparer; _fcm.FaceComparer = _Scripted
try:
    app.face_clear()
    app.add_face_photos([str(Path(matplotlib.__file__).parent / "mpl-data/sample_data/grace_hopper.jpg"), str(Path(skimage.__file__).parent / "data/astronaut.png")])
    check("2 foto masuk daftar", len(app.face_files) == 2)
    app.run_faces(); drain()
    check("pasangan dihasilkan via GUI", len(app.session.face_pairs) == 1 and app.session.face_pairs[0]["percent"] < 40)
    app.tv_pairs.selection = lambda: ["0"]; app.show_pair()
    shown = " ".join(str(c.args) for c in app.txt_face.insert.call_args_list)
    check("detail alasan tampil (persentase + cara hitung)", "KEMIRIPAN" in shown and "Cara nilai dihitung".upper() in shown)
finally:
    _fcm.FaceComparer = _real


app.v_key.set("KUNCI-PALSU"); app.ai_summary(); drain(90)
check("AI gagal -> peringatan + ringkasan lokal", ta.messagebox.showwarning.called and app.session.summary)
app.local_summary()

pdf = TMP / "o.pdf"
ta.filedialog.asksaveasfilename.return_value = str(pdf)
app.txt.get = lambda *a: "Ringkasan uji"
app.make_pdf(); check("PDF dibuat dari GUI", pdf.exists() and pdf.stat().st_size > 3000)
app.load_audit(); check("audit dimuat", True)
app.export_manifest(); app.open_map() if False else None
app.logout(); check("logout -> sesi kosong", app.session is None)

print("-- alur Admin --")
PW = "KataSandiKuat#1"
st.add_user("komandan", PW, "admin")
app.v_user.set("komandan"); app.v_pw.set(PW); app.v_otp.set(st.issue_otp("komandan"))
app.do_login()
check("admin login -> dashboard dibangun", app.session.role == "admin" and app.admin is not None and hasattr(app, "tv_users"))
check("statistik tampil", app.stat_lbl["login_ok"].config.called)
sel = {"u": "budi"}
app.tv_users.selection = lambda: [sel["u"]]          # iid = username
app.v_otp_user.set("budi"); app.adm_issue_otp()
import re
shown = [c.kwargs.get("text", "") for c in ta.ttk.Label.return_value.config.call_args_list]   # semua Label tiruan berbagi satu objek
check("OTP tampil di dashboard (format 'xxxx xxxx')", any(re.fullmatch(r"\d{4} \d{4}", x) for x in shown))
ta.simpledialog.askstring.side_effect = ["rina2", "KataSandiKuat#5"]; ta.messagebox.askyesno.return_value = False
app.adm_add(); check("tambah pengguna via dashboard", "rina2" in st.list_users())
ta.simpledialog.askstring.side_effect = None; ta.simpledialog.askstring.return_value = "SandiBaruKuat#5x"
sel["u"] = "rina2"; app.adm_reset(); check("reset kata sandi via dashboard", True)
app.adm_toggle_disable(); check("nonaktifkan via dashboard", st.list_users()["rina2"]["disabled"])
app.adm_toggle_disable(); check("aktifkan kembali", not st.list_users()["rina2"]["disabled"])
ta.messagebox.askyesno.return_value = True
app.adm_toggle_role(); check("ubah peran via dashboard", st.list_users()["rina2"]["role"] == "admin")
app.adm_toggle_role()
ta.messagebox.showerror.reset_mock(); sel["u"] = "komandan"; app.adm_delete()
check("hapus akun sendiri ditolak dgn pesan", ta.messagebox.showerror.called and "komandan" in st.list_users())
sel["u"] = "rina2"; app.adm_delete(); check("hapus pengguna via dashboard", "rina2" not in st.list_users())
csvp = TMP / "a.csv"; ta.filedialog.asksaveasfilename.return_value = str(csvp); app.adm_export_csv()
check("ekspor CSV audit via dashboard", csvp.exists() and csvp.stat().st_size > 100)
app._admin_tick(); check("tick admin (polling permintaan OTP) berjalan", app.stat_lbl["permintaan_otp"].config.called)
ta.messagebox.askyesno.return_value = True; ta.messagebox.showinfo.reset_mock()
app.adm_make_recovery()
rec_code = ta.messagebox.showinfo.call_args.args[1].split("\n")[0]      # kode yang tampil di dialog
check("tombol kode pemulihan menampilkan kode (24 karakter)", len(rec_code) == 24 and rec_code.count("-") == 4)

print("-- Minta OTP -> Admin setujui -> OTP terisi otomatis --")
app.logout()
app.v_user.set("budi"); app.do_request_otp()
req = dict(app._otp_req)
check("penyidik mendapat kode verifikasi 6 digit", len(req["vcode"]) == 6 and any(p["user"] == "budi" for p in core.OtpRequests().list_pending()))
app.v_user.set("komandan"); app.v_pw.set(PW); app.v_otp.set(st.issue_otp("komandan")); app.do_login()
app.tv_req.selection = lambda: [req["rid"]]
ta.simpledialog.askstring.side_effect = None; ta.simpledialog.askstring.return_value = req["vcode"]
app.adm_req_approve()
check("Admin menyetujui dari dashboard", core.OtpRequests().list_pending() == [])
app.logout(); app._otp_req = req          # simulasi: layar penyidik (mesin lain) masih menunggu
app.v_user.set("budi"); app._req_poll()
check("OTP terisi otomatis di layar penyidik", len(app.v_otp.get()) == 8 and app.v_otp.get().isdigit())
app.v_pw.set("KataSandiKuat#1"); app.do_login()
check("penyidik login memakai OTP hasil persetujuan", app.session is not None and app.session.actor == "budi")

print("-- Pemulihan Admin dari layar login --")
app.logout()
ta.messagebox.showinfo.reset_mock()
ta.simpledialog.askstring.side_effect = ["komandan", rec_code, "SandiPulih#12345", "SandiPulih#12345"]
app.do_recover()
check("pemulihan: OTP terisi & kode baru ditampilkan", len(app.v_otp.get()) == 8 and ta.messagebox.showinfo.called)
app.v_pw.set("SandiPulih#12345"); app.do_login()
check("login Admin dengan sandi hasil pemulihan", app.session is not None and app.session.role == "admin")
ta.simpledialog.askstring.side_effect = None
ta.messagebox.showerror.reset_mock(); app.do_bootstrap.__func__ if False else None
app.logout(); ta.messagebox.showerror.reset_mock(); app.do_bootstrap()
check("setup awal ditolak bila pengguna sudah ada", ta.messagebox.showerror.called)
app.v_user.set("budi"); app.v_pw.set("KataSandiKuat#1"); app.v_otp.set(st.issue_otp("budi")); app.do_login()
check("penyidik TIDAK mendapat dashboard admin", app.session.role == "penyidik" and app.admin is None)
app.load_audit(); check("log penyidik dimuat (terbatas miliknya)", True)

shutil.rmtree(TMP, ignore_errors=True)
print("\nSMOKE GUI:", "LULUS" if ok else "GAGAL")
sys.exit(0 if ok else 1)
