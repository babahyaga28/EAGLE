#!/usr/bin/env python3
"""triage_app.py - Aplikasi desktop EAGLE (Forensic Triage & OSINT), tkinter. Jalankan: python eagle.py"""
import os
import queue
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import osint_core as core

IDLE_LIMIT = 15 * 60          # auto-logout (zero-trust)
MODEL_DIR = Path(os.environ.get("FORENSIC_MODELS", str(core.HOME / "models")))


class App:
    def __init__(self, root):
        self.root = root
        root.title(f"{core.APP_NAME} - {core.TAGLINE}")
        root.geometry("1200x780")
        root.minsize(980, 640)
        self.session = None
        self.q = queue.Queue()
        self.cancel = threading.Event()
        self.last_touch = time.time()
        self.preview_img = None
        self.map_file = None
        self.admin = None
        self._otp_req = None
        self._req_job = None
        self._tick_job = None
        self._last_req = 0
        self._style()
        root.after(100, self._poll)
        root.after(30000, self._check_idle)
        for ev in ("<Key>", "<Button>", "<Motion>"):
            root.bind_all(ev, self._touch, add="+")
        self.show_login()

    # ------------------------------------------------------------------ util
    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        st.configure("Brand.TLabel", font=("Segoe UI", 34, "bold"), foreground="#12263f")
        st.configure("Err.TLabel", foreground="#b00020")
        st.configure("Treeview", rowheight=22)

    def _touch(self, _e=None):
        self.last_touch = time.time()

    def _check_idle(self):
        if self.session and time.time() - self.last_touch > IDLE_LIMIT:
            self.session.audit.append(self.session.actor, "AUTO_LOGOUT", {"idle_detik": IDLE_LIMIT})
            self.session = None
            messagebox.showinfo("Sesi berakhir", "Sesi ditutup otomatis karena tidak aktif.")
            self.show_login()
        self.root.after(30000, self._check_idle)

    def _poll(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def run_bg(self, work, done):
        def worker():
            try:
                res, err = work(), None
            except Exception as e:             # noqa: BLE001 - ditampilkan ke pengguna
                res, err = None, e
            self.q.put((done, (res, err)))
        threading.Thread(target=worker, daemon=True).start()

    def post_progress(self, i, n, path):
        self.q.put((self._set_progress, (i, n, path)))

    def _set_progress(self, i, n, path):
        self.pb["maximum"] = max(n, 1)
        self.pb["value"] = i
        self.lbl_status.config(text=f"[{i}/{n}] {os.path.basename(path)}")

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    @staticmethod
    def make_tree(parent, cols, widths):
        f = ttk.Frame(parent)
        tree = ttk.Treeview(f, columns=[c for c, _ in cols], show="headings", selectmode="browse")
        for (cid, title), w in zip(cols, widths):
            tree.heading(cid, text=title)
            tree.column(cid, width=w, anchor="w")
        vs = ttk.Scrollbar(f, orient="vertical", command=tree.yview)
        hs = ttk.Scrollbar(f, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)
        return f, tree

    @staticmethod
    def fill(tree, rows, tags=None, iids=None):
        tree.delete(*tree.get_children())
        for i, r in enumerate(rows):
            kw = {"iid": str(iids[i])} if iids else {}
            tree.insert("", "end", values=r, tags=((tags[i],) if tags else ()), **kw)

    # ----------------------------------------------------------------- login
    def show_login(self):
        self.clear()
        self.admin = None
        self._otp_req = None
        if self._req_job:
            self.root.after_cancel(self._req_job)
            self._req_job = None
        f = ttk.Frame(self.root, padding=30)
        f.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(f, text=core.APP_NAME, style="Brand.TLabel").grid(columnspan=2, pady=(0, 0))
        ttk.Label(f, text=core.TAGLINE, style="Title.TLabel").grid(columnspan=2, pady=(0, 4))
        ttk.Label(f, text="Akses terbatas - otentikasi dua lapis (kata sandi + OTP Komandan)").grid(columnspan=2, pady=(0, 16))
        self.v_user, self.v_pw, self.v_otp = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for r, (lbl, var, show) in enumerate([("Username", self.v_user, ""), ("Kata sandi", self.v_pw, "*"),
                                              ("OTP 8 digit", self.v_otp, "*")], start=2):
            ttk.Label(f, text=lbl).grid(row=r, column=0, sticky="e", padx=6, pady=4)
            e = ttk.Entry(f, textvariable=var, show=show, width=30)
            e.grid(row=r, column=1, pady=4)
            e.bind("<Return>", lambda _e: self.do_login())
        self.lbl_err = ttk.Label(f, text="", style="Err.TLabel", wraplength=340)
        self.lbl_err.grid(columnspan=2, pady=6)
        ttk.Button(f, text="Masuk", command=self.do_login).grid(columnspan=2, pady=6)
        ttk.Button(f, text="Minta OTP ke Admin", command=self.do_request_otp).grid(columnspan=2, pady=2)
        self.lbl_req = ttk.Label(f, text="", font=("Consolas", 22, "bold"))
        self.lbl_req.grid(columnspan=2)
        ttk.Button(f, text="Pemulihan Admin (lupa sandi / semua Admin terkunci)", command=self.do_recover).grid(columnspan=2, pady=(10, 2))
        if not core.AuthStore().has_users():
            self.lbl_err.config(text="Instalasi baru: belum ada pengguna. Buat Admin pertama di bawah.")
            ttk.Button(f, text="Setup awal: buat Admin pertama", command=self.do_bootstrap).grid(columnspan=2, pady=4)

    def do_bootstrap(self):
        name = simpledialog.askstring("Setup awal", "Username Admin pertama:")
        if not name:
            return
        pw = simpledialog.askstring("Setup awal", f"Kata sandi (min {core.MIN_PASSWORD} karakter):", show="*")
        if not pw or pw != simpledialog.askstring("Setup awal", "Ulangi kata sandi:", show="*"):
            messagebox.showerror("Setup awal", "Kata sandi kosong atau tidak sama.")
            return
        try:
            otp, recovery = core.bootstrap_admin(name.strip(), pw)
        except (ValueError, PermissionError) as e:
            messagebox.showerror("Setup awal", str(e))
            return
        self.v_user.set(name.strip())
        self.v_otp.set(otp)
        messagebox.showinfo("KODE PEMULIHAN ADMIN - SIMPAN SEKARANG",
                            f"{recovery}\n\nCetak/simpan di tempat aman (brankas). Kode ini hanya tampil SEKALI dan "
                            "dipakai bila semua Admin terkunci atau lupa sandi.")
        self.lbl_err.config(text="Admin dibuat. OTP login pertama sudah terisi otomatis (berlaku 10 menit, sekali pakai). Isi kata sandi lalu Masuk.")

    # --- Minta OTP ke Admin (tanpa terminal)
    def do_request_otp(self):
        name = self.v_user.get().strip()
        if not name:
            self.lbl_err.config(text="Isi username terlebih dahulu.")
            return
        try:
            rid, vcode = core.request_otp(name)
        except ValueError as e:
            self.lbl_err.config(text=str(e))
            return
        self._otp_req = {"rid": rid, "vcode": vcode}
        self.lbl_req.config(text=f"Kode verifikasi: {vcode[:3]} {vcode[3:]}")
        self.lbl_err.config(text="Hubungi Admin dan SEBUTKAN kode verifikasi di atas. Menunggu persetujuan; OTP akan terisi otomatis.")
        self._req_poll()

    def _req_poll(self):
        r = self._otp_req
        self._req_job = None
        if not r or self.session:
            return
        res = core.OtpRequests().poll(r["rid"], r["vcode"])
        st = res["status"]
        if st == "menunggu":
            self._req_job = self.root.after(2000, self._req_poll)
            return
        self._otp_req = None
        self.lbl_req.config(text="")
        if st == "disetujui":
            self.v_otp.set(res["otp"])
            self.lbl_err.config(text="OTP DITERIMA dan terisi otomatis. Isi kata sandi lalu tekan Masuk.")
        elif st == "ditolak":
            self.lbl_err.config(text="Permintaan DITOLAK Admin.")
        else:
            self.lbl_err.config(text="Permintaan kedaluwarsa. Tekan 'Minta OTP ke Admin' untuk mengulang.")

    # --- Pemulihan Admin (break-glass)
    def do_recover(self):
        name = simpledialog.askstring("Pemulihan Admin", "Username Admin:")
        if not name:
            return
        code = simpledialog.askstring("Pemulihan Admin", "Kode pemulihan (XXXX-XXXX-XXXX-XXXX-XXXX):")
        if not code:
            return
        pw = simpledialog.askstring("Pemulihan Admin", f"Kata sandi BARU (min {core.MIN_PASSWORD} karakter):", show="*")
        if not pw or pw != simpledialog.askstring("Pemulihan Admin", "Ulangi kata sandi baru:", show="*"):
            messagebox.showerror("Pemulihan Admin", "Kata sandi kosong atau tidak sama.")
            return
        try:
            otp, new_code = core.recover_admin(name.strip(), code, pw)
        except (core.AuthError, ValueError) as e:
            messagebox.showerror("Pemulihan Admin", str(e))
            return
        self.v_user.set(name.strip())
        self.v_pw.set("")
        self.v_otp.set(otp)
        messagebox.showinfo("Pemulihan berhasil - SIMPAN KODE BARU",
                            f"Kode pemulihan BARU (yang lama hangus):\n{new_code}\n\nSandi diganti dan akun dibuka. OTP login sudah terisi; "
                            "isi kata sandi baru lalu Masuk. Pemakaian pemulihan tercatat di log audit.")
        self.lbl_err.config(text="Pemulihan berhasil. Isi kata sandi baru lalu Masuk.")

    def do_login(self):
        try:
            self.session = core.login(self.v_user.get(), self.v_pw.get(), self.v_otp.get())
        except core.AuthError as e:
            self.lbl_err.config(text=str(e))
            self.v_pw.set("")
            self.v_otp.set("")
            return
        except Exception as e:                  # noqa: BLE001
            self.lbl_err.config(text=f"Kesalahan sistem: {e}")
            return
        self._touch()
        self.show_main()

    def logout(self):
        self.admin = None
        if self.session:
            self.session.audit.append(self.session.actor, "LOGOUT", {})
        self.session = None
        self.show_login()

    # ------------------------------------------------------------------ main
    def show_main(self):
        self.clear()
        s = self.session
        self.admin = None
        top = ttk.Frame(self.root, padding=(8, 6))
        top.pack(fill="x")
        ttk.Label(top, text=f"{core.APP_NAME}  \u2022  {core.TAGLINE}   |   Pemeriksa: {s.actor} ({s.role})").pack(side="left")
        ttk.Button(top, text="Keluar", command=self.logout).pack(side="right")
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8)
        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(fill="x")
        self.pb = ttk.Progressbar(bar, length=260)
        self.pb.pack(side="left")
        self.lbl_status = ttk.Label(bar, text="Siap.")
        self.lbl_status.pack(side="left", padx=10)
        if s.role == "admin":
            self._tab_admin()
        self._tab_case()
        self._tab_evidence()
        self._tab_findings()
        self._tab_map()
        self._tab_faces()
        self._tab_report()
        self._tab_audit()

    def _tab(self, title):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text=title)
        return f

    # --- Kasus
    def _tab_case(self):
        f = self._tab("1. Kasus")
        self.case_vars = {}
        fields = [("nomor", "Nomor perkara"), ("nama", "Nama perkara"), ("penyidik", "Penyidik / pemeriksa"),
                  ("satuan", "Satuan / instansi"), ("lokasi", "Lokasi pemeriksaan")]
        for r, (k, label) in enumerate(fields):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="e", padx=6, pady=5)
            v = tk.StringVar(value=self.session.case.get(k, ""))
            ttk.Entry(f, textvariable=v, width=60).grid(row=r, column=1, sticky="w")
            self.case_vars[k] = v
        ttk.Button(f, text="Simpan data kasus", command=self.save_case).grid(row=len(fields), column=1, sticky="w", pady=10)

    def save_case(self):
        for k, v in self.case_vars.items():
            self.session.case[k] = v.get().strip()
        self.session.audit.append(self.session.actor, "CASE_UPDATE", {"nomor": self.session.case["nomor"]})
        self.lbl_status.config(text="Data kasus disimpan.")

    # --- Barang bukti
    def _tab_evidence(self):
        f = self._tab("2. Barang Bukti")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        self.sources = []
        self.v_scan_all = tk.BooleanVar(value=False)
        ttk.Button(bar, text="Tambah folder...", command=self.add_folder).pack(side="left")
        ttk.Button(bar, text="Tambah berkas...", command=self.add_files).pack(side="left", padx=4)
        ttk.Checkbutton(bar, text="Pindai juga berkas biner", variable=self.v_scan_all).pack(side="left", padx=10)
        ttk.Button(bar, text="Mulai akuisisi & pindai", command=self.start_scan).pack(side="left")
        ttk.Button(bar, text="Batalkan", command=self.cancel.set).pack(side="left", padx=4)
        ttk.Button(bar, text="Verifikasi ulang hash", command=self.reverify).pack(side="left", padx=4)
        ttk.Button(bar, text="Ekspor manifest JSON", command=self.export_manifest).pack(side="right")
        self.lbl_sources = ttk.Label(f, text="Sumber: (belum dipilih). Akuisisi bersifat BACA-SAJA; berkas asli tidak dimodifikasi.")
        self.lbl_sources.pack(anchor="w")
        fr, self.tv_ev = self.make_tree(f, [("name", "Nama"), ("size", "Ukuran"), ("type", "Jenis isi"), ("md5", "MD5"),
                                            ("sha", "SHA-256"), ("flag", "Anomali")], [200, 80, 150, 250, 420, 70])
        fr.pack(fill="both", expand=True)
        self.tv_ev.tag_configure("bad", background="#ffe0e0")

    def add_folder(self):
        d = filedialog.askdirectory(title="Pilih folder barang bukti")
        if d:
            self.sources.append(d)
            self._src_label()

    def add_files(self):
        fs = filedialog.askopenfilenames(title="Pilih berkas barang bukti")
        if fs:
            self.sources.extend(fs)
            self._src_label()

    def _src_label(self):
        self.lbl_sources.config(text=f"Sumber ({len(self.sources)}): " + "; ".join(self.sources)[:160])

    def start_scan(self):
        if not self.sources:
            messagebox.showwarning("Belum ada sumber", "Tambahkan folder/berkas terlebih dahulu.")
            return
        self.cancel.clear()
        s, scan_all, src = self.session, self.v_scan_all.get(), list(self.sources)
        self.lbl_status.config(text="Memulai akuisisi...")
        self.run_bg(lambda: s.acquire_and_scan(src, scan_all, self.post_progress, self.cancel.is_set), self.scan_done)

    def scan_done(self, res, err):
        if err:
            messagebox.showerror("Akuisisi gagal", str(err))
            return
        self.refresh_all()
        msg = f"Selesai: {len(self.session.evidences)} bukti, {len(self.session.anomalies)} anomali."
        if self.session.errors:
            msg += f" {len(self.session.errors)} berkas gagal dibaca."
        self.lbl_status.config(text=msg)

    def reverify(self):
        s = self.session
        self.run_bg(s.reverify, self._reverify_done)

    def _reverify_done(self, res, err):
        if err:
            messagebox.showerror("Gagal", str(err))
            return
        bad = [r for r in res if not r["ok"]]
        if bad:
            messagebox.showwarning("Hash BERUBAH", f"{len(bad)} berkas tidak lagi cocok:\n" + "\n".join(os.path.basename(b["file"]) for b in bad[:10]))
        else:
            messagebox.showinfo("Hash cocok", f"Seluruh {len(res)} berkas identik dengan saat akuisisi.")

    def export_manifest(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", initialfile="manifest_bukti.json")
        if p:
            self.session.export_manifest(p)
            self.lbl_status.config(text=f"Manifest disimpan: {p}")

    # --- Temuan
    def _tab_findings(self):
        f = self._tab("3. Temuan")
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        a = ttk.LabelFrame(pw, text="Anomali berkas (ekstensi palsu, ekstensi ganda, entropi)", padding=4)
        fr, self.tv_an = self.make_tree(a, [("sev", "Tingkat"), ("file", "Berkas"), ("why", "Keterangan")], [80, 260, 700])
        fr.pack(fill="both", expand=True)
        self.tv_an.tag_configure("TINGGI", background="#ffd6d6")
        self.tv_an.tag_configure("SEDANG", background="#fff3cd")
        b = ttk.LabelFrame(pw, text="Data sensitif (Bitcoin ber-checksum valid & email)", padding=4)
        fr2, self.tv_fd = self.make_tree(b, [("type", "Jenis"), ("val", "Nilai"), ("file", "Berkas"), ("off", "Offset")], [80, 420, 300, 90])
        fr2.pack(fill="both", expand=True)
        pw.add(a, weight=1)
        pw.add(b, weight=1)

    # --- Peta
    def _tab_map(self):
        f = self._tab("4. Peta GPS")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Buka peta interaktif (browser)", command=self.open_map).pack(side="left")
        ttk.Button(bar, text="Simpan peta HTML...", command=self.save_map).pack(side="left", padx=4)
        ttk.Button(bar, text="Ekspor KML...", command=self.save_kml).pack(side="left")
        pw = ttk.PanedWindow(f, orient="horizontal")
        pw.pack(fill="both", expand=True)
        fr, self.tv_gps = self.make_tree(pw, [("file", "Berkas"), ("lat", "Lat"), ("lon", "Lon"), ("dev", "Perangkat"), ("t", "Waktu")], [180, 80, 80, 120, 130])
        self.cv = tk.Canvas(pw, bg="#f4f7fb", width=460, height=420, highlightthickness=1)
        pw.add(fr, weight=1)
        pw.add(self.cv, weight=1)
        self.cv.bind("<Configure>", lambda _e: self.draw_plot())

    def draw_plot(self):
        c = self.cv
        c.delete("all")
        pts = self.session.gps if self.session else []
        w, h = max(c.winfo_width(), 200), max(c.winfo_height(), 200)
        if not pts:
            c.create_text(w / 2, h / 2, text="Belum ada titik GPS", fill="#667")
            return
        lats, lons = [p["lat"] for p in pts], [p["lon"] for p in pts]
        pad = 50
        lo_la, hi_la, lo_lo, hi_lo = min(lats), max(lats), min(lons), max(lons)
        span_la, span_lo = max(hi_la - lo_la, 1e-4), max(hi_lo - lo_lo, 1e-4)
        for i in range(5):
            x, y = pad + i * (w - 2 * pad) / 4, pad + i * (h - 2 * pad) / 4
            c.create_line(x, pad, x, h - pad, fill="#dde")
            c.create_line(pad, y, w - pad, y, fill="#dde")
        for p in pts:
            x = pad + (p["lon"] - lo_lo) / span_lo * (w - 2 * pad)
            y = h - pad - (p["lat"] - lo_la) / span_la * (h - 2 * pad)
            c.create_oval(x - 5, y - 5, x + 5, y + 5, fill="#d32f2f", outline="")
            c.create_text(x + 8, y - 8, text=os.path.basename(p["file"])[:18], anchor="w", font=("Segoe UI", 8))
        c.create_text(pad, h - 14, anchor="w", fill="#556", font=("Segoe UI", 8),
                      text=f"Lon {lo_lo:.4f}..{hi_lo:.4f}   Lat {lo_la:.4f}..{hi_la:.4f}   (plot offline; peta dasar: tombol di atas)")

    def open_map(self):
        if not self.session.gps:
            messagebox.showinfo("Peta", "Belum ada titik GPS.")
            return
        p = os.path.join(tempfile.gettempdir(), f"peta_bukti_{os.getpid()}.html")
        self.session.export_map(p)
        webbrowser.open("file://" + p.replace("\\", "/"))

    def save_map(self):
        p = filedialog.asksaveasfilename(defaultextension=".html", initialfile="peta_bukti.html")
        if p:
            self.session.export_map(p)

    def save_kml(self):
        p = filedialog.asksaveasfilename(defaultextension=".kml", initialfile="lokasi_bukti.kml")
        if p:
            self.session.export_kml(p)

    # --- Pengenalan wajah: bandingkan 2+ foto -> persentase + alasan
    def _tab_faces(self):
        f = self._tab("5. Pengenal Wajah")
        self.face_files = []
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        for text, cmd in [("Tambah foto...", self.face_add_files), ("Dari barang bukti...", self.face_pick_evidence),
                          ("Hapus terpilih", self.face_remove), ("Kosongkan", self.face_clear)]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)
        ttk.Button(bar, text="Bandingkan sekarang", command=self.run_faces).pack(side="left", padx=(14, 2))
        ttk.Label(f, wraplength=1120, text=f"Pilih 2 sampai {core.MAX_PHOTOS} foto. Setiap pasangan dibandingkan: hasilnya persentase kemiripan beserta ciri yang mirip/berbeda dan "
                  "cara nilai dihitung. Persentase adalah skor kemiripan visual, BUKAN probabilitas identitas; wajib diverifikasi manusia. "
                  f"Model SFace/YuNet (opsional, lebih akurat) diletakkan di: {MODEL_DIR}").pack(anchor="w", pady=(0, 6))
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        top = ttk.PanedWindow(pw, orient="horizontal")
        fr1, self.tv_photos = self.make_tree(top, [("n", "No"), ("name", "Foto"), ("st", "Status")], [40, 230, 260])
        fr2, self.tv_pairs = self.make_tree(top, [("pair", "Pasangan"), ("pct", "Kemiripan"), ("verdict", "Putusan"), ("conf", "Keyakinan")], [150, 90, 230, 90])
        top.add(fr1, weight=1)
        top.add(fr2, weight=1)
        self.tv_pairs.tag_configure("hi", background="#ffe0e0")
        self.tv_pairs.tag_configure("mid", background="#fff3cd")
        self.tv_pairs.bind("<<TreeviewSelect>>", self.show_pair)
        bottom = ttk.PanedWindow(pw, orient="horizontal")
        self.lbl_cmp_img = ttk.Label(bottom, text="(pilih satu pasangan untuk melihat citra perbandingan)")
        txt_fr = ttk.Frame(bottom)
        self.txt_face = tk.Text(txt_fr, wrap="word", height=14, width=60)
        sb = ttk.Scrollbar(txt_fr, orient="vertical", command=self.txt_face.yview)
        self.txt_face.configure(yscrollcommand=sb.set, state="disabled")
        self.txt_face.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        bottom.add(self.lbl_cmp_img, weight=1)
        bottom.add(txt_fr, weight=1)
        pw.add(top, weight=1)
        pw.add(bottom, weight=2)

    def add_face_photos(self, paths):
        for p in paths:
            rp = os.path.realpath(str(p))
            if all(os.path.realpath(q) != rp for q in self.face_files):
                if len(self.face_files) >= core.MAX_PHOTOS:
                    messagebox.showwarning("Batas foto", f"Maksimal {core.MAX_PHOTOS} foto sekaligus.")
                    break
                self.face_files.append(str(p))
        self._fill_photos()

    def _fill_photos(self):
        info = {ph["path"]: ph for ph in (self.session.face_photos if self.session else [])}
        rows = []
        for i, p in enumerate(self.face_files, 1):
            ph = info.get(p)
            st = "belum dianalisis" if ph is None else (f"wajah terdeteksi; mata: {ph['metode_mata']}" if ph["ok"] else ph["note"])
            rows.append((i, core.visible(os.path.basename(p)), st))
        self.fill(self.tv_photos, rows, None, [str(i) for i in range(len(rows))])

    def face_add_files(self):
        fs = filedialog.askopenfilenames(title="Pilih foto wajah", filetypes=[("Gambar", "*.jpg *.jpeg *.png *.bmp *.webp"), ("Semua", "*.*")])
        if fs:
            self.add_face_photos(fs)

    def face_pick_evidence(self):
        imgs = [e for e in self.session.evidences if e.sig_kind in ("jpeg", "png", "gif", "riff") or e.ext in core.IMAGE_EXT]
        if not imgs:
            messagebox.showinfo("Barang bukti", "Belum ada gambar pada barang bukti yang diakuisisi.")
            return
        win = tk.Toplevel(self.root)
        win.title("Pilih foto dari barang bukti")
        win.geometry("520x380")
        lb = tk.Listbox(win, selectmode="extended")
        lb.pack(fill="both", expand=True, padx=8, pady=8)
        for e in imgs:
            lb.insert("end", e.name)

        def ok():
            self.add_face_photos([imgs[i].path for i in lb.curselection()])
            win.destroy()
        ttk.Button(win, text="Tambahkan", command=ok).pack(pady=(0, 8))

    def face_remove(self):
        sel = self.tv_photos.selection()
        if sel:
            del self.face_files[int(sel[0])]
            self._fill_photos()

    def face_clear(self):
        self.face_files = []
        self.session.face_photos, self.session.face_pairs = [], []
        self._fill_photos()
        self.refresh_faces()

    def run_faces(self):
        if len(self.face_files) < 2:
            messagebox.showwarning("Pengenal wajah", "Pilih minimal 2 foto untuk dibandingkan.")
            return
        s, files = self.session, list(self.face_files)
        self.cancel.clear()
        self.lbl_status.config(text="Menganalisis dan membandingkan wajah...")
        self.run_bg(lambda: s.compare_faces(files, MODEL_DIR, self.post_progress, self.cancel.is_set), self.faces_done)

    def faces_done(self, res, err):
        if err:
            messagebox.showerror("Pengenal wajah", str(err))
            return
        self.refresh_faces()
        if not res:
            bad = [ph["note"] for ph in self.session.face_photos if not ph["ok"]]
            messagebox.showwarning("Tidak ada pasangan yang dapat dibandingkan", bad[0] if bad else "Wajah tidak terdeteksi pada foto-foto tersebut.")
        top = max(res, key=lambda p: p["percent"]) if res else None
        self.lbl_status.config(text=(f"Selesai: {len(res)} pasangan; tertinggi {core.fmt_pct(top['percent'])} ({top['verdict']})." if top else "Selesai: tidak ada pasangan."))

    def refresh_faces(self):
        s = self.session
        self._fill_photos()
        rows, tags = [], []
        for p in s.face_pairs:
            rows.append((f"Foto {p['a'] + 1} \u2194 Foto {p['b'] + 1}", core.fmt_pct(p["percent"]), p["verdict"], p["confidence"]))
            tags.append("hi" if p["percent"] >= 70 else ("mid" if p["percent"] >= 50 else ""))
        self.fill(self.tv_pairs, rows, tags, [str(i) for i in range(len(rows))])
        self.txt_face.config(state="normal")
        self.txt_face.delete("1.0", "end")
        self.txt_face.config(state="disabled")

    def show_pair(self, _e=None):
        sel = self.tv_pairs.selection()
        if not sel or not self.session.face_pairs:
            return
        import face_compare
        p = self.session.face_pairs[int(sel[0])]
        self.txt_face.config(state="normal")
        self.txt_face.delete("1.0", "end")
        self.txt_face.insert("1.0", f"KEMIRIPAN {core.fmt_pct(p['percent'])} - {p['verdict']} (keyakinan {p['confidence']})\n\n" +
                             face_compare.format_pair_text(p, self.session.face_photos))
        self.txt_face.config(state="disabled")
        try:
            from io import BytesIO
            from PIL import Image, ImageTk
            im = Image.open(BytesIO(p["image_png"])).convert("RGB")
            im.thumbnail((640, 560))
            self.preview_img = ImageTk.PhotoImage(im)
            self.lbl_cmp_img.config(image=self.preview_img, text="")
        except Exception:                      # noqa: BLE001
            self.lbl_cmp_img.config(image="", text="(citra tidak dapat ditampilkan)")

    # --- AI & Laporan
    def _tab_report(self):
        f = self._tab("6. AI & Laporan")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="Kunci API Gemini:").pack(side="left")
        self.v_key = tk.StringVar(value=os.environ.get("GEMINI_API_KEY", ""))
        ttk.Entry(bar, textvariable=self.v_key, show="*", width=34).pack(side="left", padx=4)
        ttk.Label(bar, text="Model:").pack(side="left")
        self.v_model = tk.StringVar(value=core.DEFAULT_GEMINI_MODEL)
        ttk.Entry(bar, textvariable=self.v_model, width=18).pack(side="left", padx=4)
        self.v_redact = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Samarkan data sensitif ke AI", variable=self.v_redact).pack(side="left", padx=8)
        bar2 = ttk.Frame(f)
        bar2.pack(fill="x", pady=(0, 6))
        ttk.Button(bar2, text="Susun ringkasan (Gemini)", command=self.ai_summary).pack(side="left")
        ttk.Button(bar2, text="Ringkasan lokal (offline)", command=self.local_summary).pack(side="left", padx=4)
        ttk.Button(bar2, text="Buat PDF Berita Acara Pemeriksaan", command=self.make_pdf).pack(side="right")
        ttk.Label(f, text="Hanya ringkasan terstruktur yang dikirim ke Gemini (bukan isi berkas). Hasil AI adalah DRAF - periksa sebelum dipakai.").pack(anchor="w")
        self.txt = tk.Text(f, wrap="word", height=20)
        self.txt.pack(fill="both", expand=True, pady=6)

    def _set_text(self, t):
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", t)

    def local_summary(self):
        text, _ = self.session.make_summary("")
        self._set_text(text)

    def ai_summary(self):
        key = self.v_key.get().strip()
        if not key:
            messagebox.showwarning("Gemini", "Isi kunci API Gemini, atau gunakan ringkasan lokal.")
            return
        s, model, red = self.session, self.v_model.get().strip(), self.v_redact.get()
        self.lbl_status.config(text="Menghubungi Gemini...")
        self.run_bg(lambda: s.make_summary(key, model, red), self._ai_done)

    def _ai_done(self, res, err):
        if err:
            messagebox.showerror("Gemini", str(err))
            return
        text, problem = res
        self._set_text(text)
        if problem:
            messagebox.showwarning("Gemini gagal - memakai ringkasan lokal", problem)
        self.lbl_status.config(text="Ringkasan siap (silakan tinjau/ubah).")

    def make_pdf(self):
        if not self.session.evidences:
            messagebox.showwarning("Laporan", "Belum ada barang bukti.")
            return
        self.save_case()
        self.session.summary = self.txt.get("1.0", "end").strip() or core.local_summary(self.session)
        p = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="Berita_Acara_Pemeriksaan.pdf")
        if not p:
            return
        try:
            self.session.make_pdf(p)
        except Exception as e:                  # noqa: BLE001
            messagebox.showerror("PDF gagal", str(e))
            return
        self.lbl_status.config(text=f"PDF dibuat: {p}")
        messagebox.showinfo("Selesai", f"Berita Acara tersimpan:\n{p}")


    # --- Dashboard Admin
    def _tab_admin(self):
        self.admin = core.AdminService(self.session)
        f = self._tab("A. Dashboard Admin")
        sub = ttk.Notebook(f)
        sub.pack(fill="both", expand=True)

        # Ringkasan
        t1 = ttk.Frame(sub, padding=10)
        sub.add(t1, text="Ringkasan")
        self.stat_lbl = {}
        cards = [("login_ok", "Login sukses (24 jam)"), ("login_fail", "Login gagal (24 jam)"), ("locked", "Akun terkunci"),
                 ("otp_aktif", "OTP aktif"), ("users", "Total pengguna"), ("akuisisi", "Berkas diakuisisi (24 jam)"),
                 ("pdf", "PDF dibuat (24 jam)"), ("ai", "Ringkasan AI (24 jam)"), ("permintaan_otp", "Permintaan OTP menunggu")]
        for i, (k, label) in enumerate(cards):
            lf = ttk.LabelFrame(t1, text=label, padding=10)
            lf.grid(row=i // 4, column=i % 4, padx=6, pady=6, sticky="nsew")
            lab = ttk.Label(lf, text="-", font=("Segoe UI", 22, "bold"))
            lab.pack()
            self.stat_lbl[k] = lab
            t1.columnconfigure(i % 4, weight=1)
        self.lbl_chain_admin = ttk.Label(t1, text="", font=("Segoe UI", 12, "bold"))
        self.lbl_chain_admin.grid(row=3, column=0, columnspan=4, sticky="w", pady=(14, 2))
        self.lbl_alert = ttk.Label(t1, text="", style="Err.TLabel", wraplength=900)
        self.lbl_alert.grid(row=4, column=0, columnspan=4, sticky="w")
        ttk.Button(t1, text="Segarkan", command=self.admin_refresh).grid(row=5, column=0, sticky="w", pady=10)
        ttk.Button(t1, text="Buat/ganti kode pemulihan saya", command=self.adm_make_recovery).grid(row=5, column=1, columnspan=2, sticky="w", pady=10)

        # Permintaan OTP
        t5 = ttk.Frame(sub, padding=8)
        sub.add(t5, text="Permintaan OTP")
        ttk.Label(t5, wraplength=900, text="Penyidik meminta OTP dari layar login. TELEPON/temui penyidik, minta ia menyebutkan KODE VERIFIKASI "
                  "di layarnya, lalu ketik kode itu saat menyetujui. OTP langsung terkirim ke layar penyidik (terenkripsi, baca-sekali).").pack(anchor="w", pady=(0, 6))
        bar5 = ttk.Frame(t5)
        bar5.pack(fill="x", pady=(0, 6))
        ttk.Button(bar5, text="Setujui...", command=self.adm_req_approve).pack(side="left", padx=2)
        ttk.Button(bar5, text="Tolak", command=self.adm_req_reject).pack(side="left", padx=2)
        fr, self.tv_req = self.make_tree(t5, [("t", "Diminta"), ("user", "Pengguna"), ("known", "Terdaftar"), ("left", "Sisa waktu"), ("tries", "Salah kode")],
                                         [170, 180, 120, 100, 100])
        fr.pack(fill="both", expand=True)
        self.tv_req.tag_configure("unk", background="#ffd6d6")

        # Pengguna
        t2 = ttk.Frame(sub, padding=8)
        sub.add(t2, text="Pengguna")
        bar = ttk.Frame(t2)
        bar.pack(fill="x", pady=(0, 6))
        for text, cmd in [("Tambah pengguna", self.adm_add), ("Reset kata sandi", self.adm_reset), ("Buka kunci", self.adm_unlock),
                          ("Aktif/Nonaktifkan", self.adm_toggle_disable), ("Ubah peran", self.adm_toggle_role), ("Hapus", self.adm_delete)]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)
        fr, self.tv_users = self.make_tree(t2, [("user", "Username"), ("role", "Peran"), ("status", "Status"), ("fails", "Gagal"),
                                                ("last", "Login terakhir (UTC)"), ("created", "Dibuat (UTC)")], [160, 90, 100, 60, 200, 200])
        fr.pack(fill="both", expand=True)
        self.tv_users.tag_configure("warn", background="#fff3cd")
        self.tv_users.tag_configure("off", background="#e6e6e6")

        # OTP
        t3 = ttk.Frame(sub, padding=10)
        sub.add(t3, text="Terbitkan OTP")
        row = ttk.Frame(t3)
        row.pack(fill="x")
        ttk.Label(row, text="Untuk pengguna:").pack(side="left")
        self.v_otp_user = tk.StringVar()
        self.cmb_user = ttk.Combobox(row, textvariable=self.v_otp_user, width=24, state="readonly")
        self.cmb_user.pack(side="left", padx=6)
        ttk.Label(row, text="Berlaku (menit):").pack(side="left")
        self.v_otp_ttl = tk.IntVar(value=10)
        ttk.Spinbox(row, from_=1, to=60, textvariable=self.v_otp_ttl, width=5).pack(side="left", padx=6)
        ttk.Button(row, text="Terbitkan OTP", command=self.adm_issue_otp).pack(side="left", padx=6)
        self.lbl_otp = ttk.Label(t3, text="", font=("Consolas", 34, "bold"))
        self.lbl_otp.pack(pady=(14, 0))
        self.lbl_otp_note = ttk.Label(t3, text="Kode hanya tampil sekali dan tidak tersimpan. Sampaikan lewat kanal terpisah.")
        self.lbl_otp_note.pack(pady=(0, 10))
        ttk.Button(t3, text="Cabut OTP terpilih", command=self.adm_revoke_otp).pack(anchor="w")
        fr, self.tv_otp = self.make_tree(t3, [("user", "Pengguna"), ("exp", "Kedaluwarsa"), ("id", "ID")], [200, 220, 200])
        fr.pack(fill="both", expand=True, pady=6)

        # Aktivitas
        t4 = ttk.Frame(sub, padding=8)
        sub.add(t4, text="Aktivitas & Audit")
        flt = ttk.Frame(t4)
        flt.pack(fill="x", pady=(0, 6))
        self.v_f_actor, self.v_f_action, self.v_f_text = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for lbl, var, w in [("Aktor", self.v_f_actor, 14), ("Aksi", self.v_f_action, 16), ("Kata kunci", self.v_f_text, 22)]:
            ttk.Label(flt, text=lbl).pack(side="left", padx=(8, 2))
            ttk.Entry(flt, textvariable=var, width=w).pack(side="left")
        ttk.Button(flt, text="Terapkan", command=self.adm_load_activity).pack(side="left", padx=6)
        ttk.Button(flt, text="Ekspor CSV...", command=self.adm_export_csv).pack(side="right")
        fr, self.tv_act = self.make_tree(t4, [("ts", "Waktu (UTC)"), ("actor", "Aktor"), ("act", "Aksi"), ("det", "Rincian")], [170, 120, 170, 650])
        fr.pack(fill="both", expand=True)
        self.tv_act.tag_configure("fail", background="#ffd6d6")
        self.admin_refresh()
        if self._tick_job:
            self.root.after_cancel(self._tick_job)
        self._tick_job = self.root.after(4000, self._admin_tick)

    def _admin_do(self, fn, ok_msg=None):
        try:
            res = fn()
        except (ValueError, PermissionError, TimeoutError) as e:
            messagebox.showerror("Dashboard Admin", str(e))
            if isinstance(e, PermissionError):
                self.logout()
            return None
        self.admin_refresh()
        if ok_msg:
            self.lbl_status.config(text=ok_msg)
        return res

    def _sel_user(self):
        sel = self.tv_users.selection()
        if not sel:
            messagebox.showinfo("Pengguna", "Pilih pengguna pada daftar terlebih dahulu.")
            return None
        return str(sel[0])                  # iid = username (aman dari konversi angka oleh Tk)

    def adm_add(self):
        name = simpledialog.askstring("Tambah pengguna", "Username (3-32: huruf, angka, _ . -):")
        if not name:
            return
        pw = simpledialog.askstring("Tambah pengguna", f"Kata sandi awal (min {core.MIN_PASSWORD} karakter):", show="*")
        if not pw:
            return
        role = "admin" if messagebox.askyesno("Peran", "Jadikan ADMIN? (Tidak = penyidik)") else "penyidik"
        self._admin_do(lambda: self.admin.add_user(name.strip(), pw, role), f"Pengguna '{name.strip()}' dibuat.")

    def adm_reset(self):
        u = self._sel_user()
        if u:
            pw = simpledialog.askstring("Reset kata sandi", f"Kata sandi baru untuk {u}:", show="*")
            if pw:
                self._admin_do(lambda: self.admin.reset_password(u, pw), f"Kata sandi {u} diganti; OTP lama dicabut.")

    def adm_unlock(self):
        u = self._sel_user()
        if u:
            self._admin_do(lambda: self.admin.unlock(u), f"Akun {u} dibuka.")

    def adm_toggle_disable(self):
        u = self._sel_user()
        if u:
            now_off = self.admin.users().get(u, {}).get("disabled", False)
            self._admin_do(lambda: self.admin.set_disabled(u, not now_off), f"Akun {u} {'diaktifkan' if now_off else 'dinonaktifkan'}.")

    def adm_toggle_role(self):
        u = self._sel_user()
        if u:
            cur = self.admin.users().get(u, {}).get("role")
            new = "penyidik" if cur == "admin" else "admin"
            if messagebox.askyesno("Ubah peran", f"Ubah peran {u}: {cur} -> {new}?"):
                self._admin_do(lambda: self.admin.set_role(u, new), f"Peran {u} menjadi {new}.")

    def adm_delete(self):
        u = self._sel_user()
        if u and messagebox.askyesno("Hapus pengguna", f"Hapus '{u}' secara permanen?"):
            self._admin_do(lambda: self.admin.delete_user(u), f"Pengguna {u} dihapus.")

    def adm_issue_otp(self):
        u = self.v_otp_user.get()
        if not u:
            messagebox.showinfo("OTP", "Pilih pengguna terlebih dahulu.")
            return
        res = self._admin_do(lambda: self.admin.issue_otp(u, int(self.v_otp_ttl.get())))
        if res:
            code, exp = res
            self.lbl_otp.config(text=f"{code[:4]} {code[4:]}")
            self.lbl_otp_note.config(text=f"OTP untuk {u}, berlaku hingga {time.strftime('%H:%M:%S', time.localtime(exp))}. Sekali pakai; tidak tersimpan.")

    def adm_revoke_otp(self):
        sel = self.tv_otp.selection()
        if not sel:
            messagebox.showinfo("OTP", "Pilih OTP pada daftar.")
            return
        oid = str(sel[0])                   # iid = id OTP
        self._admin_do(lambda: self.admin.revoke_otp(oid), "OTP dicabut.")

    def _fill_requests(self, pend):
        now = time.time()
        self.fill(self.tv_req, [(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created"])), r["user"],
                                 "ya" if r["dikenal"] else "TIDAK DIKENAL", f"{int(r['exp'] - now) // 60}m {int(r['exp'] - now) % 60:02d}s", r["tries"])
                                for r in pend], ["" if r["dikenal"] else "unk" for r in pend], [r["rid"] for r in pend])

    def _admin_tick(self):
        self._tick_job = None
        if not (self.session and self.admin):
            return
        try:
            pend = self.admin.otp_requests()
        except PermissionError:
            return
        if len(pend) > self._last_req:
            self.root.bell()
            self.lbl_status.config(text=f"{len(pend)} permintaan OTP menunggu persetujuan.")
        self._last_req = len(pend)
        self._fill_requests(pend)
        self.stat_lbl["permintaan_otp"].config(text=str(len(pend)))
        self._tick_job = self.root.after(4000, self._admin_tick)

    def adm_req_approve(self):
        sel = self.tv_req.selection()
        if not sel:
            messagebox.showinfo("Permintaan OTP", "Pilih permintaan pada daftar.")
            return
        rid = str(sel[0])
        vcode = simpledialog.askstring("Setujui OTP", "Ketik KODE VERIFIKASI yang disebutkan penyidik\n(yang tampil di layar login penyidik):")
        if not vcode:
            return
        res = self._admin_do(lambda: self.admin.approve_otp_request(rid, vcode, int(self.v_otp_ttl.get())))
        if res:
            self.lbl_status.config(text=f"OTP untuk {res} disetujui dan terkirim ke layar login-nya.")

    def adm_req_reject(self):
        sel = self.tv_req.selection()
        if sel:
            self._admin_do(lambda: self.admin.reject_otp_request(str(sel[0])), "Permintaan ditolak.")

    def adm_make_recovery(self):
        if not messagebox.askyesno("Kode pemulihan", "Buat kode pemulihan BARU untuk akun Anda?\nKode lama (jika ada) langsung tidak berlaku."):
            return
        code = self._admin_do(self.admin.make_recovery_code)
        if code:
            messagebox.showinfo("KODE PEMULIHAN - SIMPAN SEKARANG", f"{code}\n\nCetak/simpan di tempat aman. Hanya tampil SEKALI.")

    def adm_load_activity(self):
        try:
            rows = self.admin.audit_rows(self.v_f_actor.get(), self.v_f_action.get(), self.v_f_text.get())
        except PermissionError as e:
            messagebox.showerror("Dashboard Admin", str(e))
            return
        self.fill(self.tv_act, [(e["ts"], e["actor"], e["action"], str(e["detail"])[:300]) for e in rows],
                  ["fail" if e["action"] in ("LOGIN_FAIL", "LOGIN_LOCKED") else "" for e in rows])

    def adm_export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="audit_log.csv")
        if p:
            n = self._admin_do(lambda: self.admin.export_audit_csv(p))
            if n is not None:
                self.lbl_status.config(text=f"{n} entri diekspor ke {p}")

    def admin_refresh(self):
        try:
            st = self.admin.stats(24)
            users = self.admin.users()
            otps = self.admin.pending_otps()
        except PermissionError as e:
            messagebox.showerror("Dashboard Admin", str(e))
            self.logout()
            return
        for k, lab in self.stat_lbl.items():
            lab.config(text=str(st[k]))
        self.lbl_chain_admin.config(text=(f"Rantai log audit: UTUH ({st['chain_n']} entri)" if st["chain_ok"]
                                          else f"Rantai log audit: RUSAK mulai entri #{st['chain_bad']} - hentikan penggunaan laporan"),
                                    foreground=("#1b5e20" if st["chain_ok"] else "#b00020"))
        alerts = []
        if st["mencurigakan"]:
            alerts.append("PERINGATAN: login gagal berulang (>=3) pada: " + ", ".join(st["mencurigakan"]))
        if st["pemulihan_dipakai"]:
            alerts.append("KODE PEMULIHAN DIPAKAI (24 jam) oleh: " + ", ".join(st["pemulihan_dipakai"]) + " - pastikan sah.")
        if st["tanpa_pemulihan"]:
            alerts.append("Admin tanpa kode pemulihan: " + ", ".join(st["tanpa_pemulihan"]) + " (buat lewat tombol di bawah).")
        self.lbl_alert.config(text="\n".join(alerts))
        now = time.time()
        rows, tags = [], []
        for u, d in users.items():
            status = "nonaktif" if d["disabled"] else ("TERKUNCI" if d["locked_until"] > now else "aktif")
            rows.append((u, d["role"], status, d["fails"], d["last_login"] or "-", d["created"] or "-"))
            tags.append("off" if d["disabled"] else ("warn" if status == "TERKUNCI" else ""))
        self.fill(self.tv_users, rows, tags, list(users))
        self.cmb_user["values"] = [u for u, d in users.items() if not d["disabled"]]
        self.fill(self.tv_otp, [(o["user"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(o["exp"])), o["id"]) for o in otps],
                  None, [o["id"] for o in otps])
        self._fill_requests(self.admin.otp_requests())
        self.adm_load_activity()

    # --- Audit
    def _tab_audit(self):
        f = self._tab("7. Chain of Custody")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Muat & verifikasi log", command=self.load_audit).pack(side="left")
        self.lbl_chain = ttk.Label(bar, text="")
        self.lbl_chain.pack(side="left", padx=10)
        fr, self.tv_audit = self.make_tree(f, [("ts", "Waktu (UTC)"), ("actor", "Aktor"), ("act", "Aksi"), ("det", "Rincian")], [170, 110, 150, 700])
        fr.pack(fill="both", expand=True)
        self.nb.bind("<<NotebookTabChanged>>", lambda _e: self.draw_plot())

    def load_audit(self):
        ok, n, bad = self.session.audit.verify()
        self.lbl_chain.config(text=(f"UTUH - {n} entri" if ok else f"RUSAK mulai entri #{bad}"), foreground=("#1b5e20" if ok else "#b00020"))
        entries = self.session.audit.read()
        if self.session.role != "admin":          # least-privilege: penyidik hanya melihat aktivitasnya sendiri
            entries = [e for e in entries if e.get("actor") == self.session.actor]
        rows = [(e.get("ts", "?"), e.get("actor", "?"), e.get("action", "CORRUPT"), str(e.get("detail", ""))[:300]) for e in entries]
        self.fill(self.tv_audit, list(reversed(rows)))

    # --- refresh
    def refresh_all(self):
        s = self.session
        bad = {a["file"] for a in s.anomalies}
        self.fill(self.tv_ev, [(core.visible(e.name), f"{e.size:,}", e.sig_label, e.md5, e.sha256, "!" if e.path in bad else "") for e in s.evidences],
                  ["bad" if e.path in bad else "" for e in s.evidences])
        order = sorted(s.anomalies, key=lambda a: a["severity"] != "TINGGI")
        self.fill(self.tv_an, [(a["severity"], core.visible(os.path.basename(a["file"])), core.visible(a["reason"])) for a in order], [a["severity"] for a in order])
        self.fill(self.tv_fd, [("Bitcoin" if f["type"] == "bitcoin" else "Email", f["value"], core.visible(os.path.basename(f["file"])), f["offset"]) for f in s.findings])
        self.fill(self.tv_gps, [(core.visible(os.path.basename(g["file"])), g["lat"], g["lon"], g["device"], g["taken"]) for g in s.gps])
        self.draw_plot()
        self.refresh_faces()
        self.load_audit()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
