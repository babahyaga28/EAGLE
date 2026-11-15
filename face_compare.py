#!/usr/bin/env python3
"""
face_compare.py - Pengenalan wajah: membandingkan 2+ foto, menghasilkan PERSENTASE kemiripan
beserta ALASAN yang diturunkan dari pengukuran (bukan karangan).

Cara kerja:
  1. Deteksi wajah + mata. Detektor: Haar (OpenCV 4.x) atau YuNet (model ONNX, semua versi OpenCV).
     OpenCV 5 TIDAK menyertakan Haar, jadi di sana wajib memasang model YuNet+SFace atau memakai OpenCV 4.x.
  2. Wajah diluruskan & diskalakan berdasarkan posisi mata, lalu dibagi 6 wilayah (dahi, dua mata, hidung,
     mulut, dagu/rahang). Tiap wilayah dibandingkan dengan 3 ukuran: korelasi pola (toleran pergeseran kecil),
     kesamaan arah tepi, dan kesamaan tekstur (LBP).
  3. Bila kedua mata terdeteksi, proporsi wajah (jarak mata, tinggi mata) ikut dibandingkan.
  4. Opsional: model SFace -> skor embedding ikut dihitung.
  5. Persentase = jumlah berbobot komponen; rincian & alasan dilaporkan apa adanya.

PENTING: persentase adalah SKOR KEMIRIPAN VISUAL RELATIF, bukan probabilitas identitas. Pemetaan skor
bersifat heuristik dan belum dikalibrasi dengan dataset berlabel besar. Hasil wajib diverifikasi manusia.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
from typing import Optional

FACE_W, FACE_H = 128, 144
EYE_L, EYE_R = (38.0, 52.0), (90.0, 52.0)
# (nama, (x0,y0,x1,y1) pada wajah terluruskan 128x144, bobot)
REGIONS = [
    ("Dahi", (20, 6, 108, 40), 0.12),
    ("Mata (kiri foto)", (12, 40, 64, 68), 0.17),
    ("Mata (kanan foto)", (64, 40, 116, 68), 0.17),
    ("Hidung", (42, 56, 86, 98), 0.20),
    ("Mulut", (30, 96, 98, 124), 0.18),
    ("Dagu & rahang", (22, 120, 106, 144), 0.16),
]
SHORT = {"Dahi": "Dahi", "Mata (kiri foto)": "Mata-K", "Mata (kanan foto)": "Mata-R", "Hidung": "Hidung",
         "Mulut": "Mulut", "Dagu & rahang": "Dagu"}
CAUSES = {
    "Dahi": "rambut/poni/topi atau perbedaan pencahayaan",
    "Mata (kiri foto)": "kacamata, arah pandang, kelopak mata yang terbuka/menyipit, atau riasan",
    "Mata (kanan foto)": "kacamata, arah pandang, kelopak mata yang terbuka/menyipit, atau riasan",
    "Hidung": "bayangan/pencahayaan atau sudut kepala yang berbeda",
    "Mulut": "ekspresi (tersenyum/terbuka), kumis, atau janggut",
    "Dagu & rahang": "janggut, bayangan, atau sudut kepala yang berbeda",
}
# Pemetaan skor mentah -> 0..1 (HEURISTIK; lihat catatan kalibrasi di docstring)
NCC_RANGE, HOG_RANGE, LBP_RANGE = (0.30, 0.90), (0.70, 0.98), (0.45, 0.85)
METRIC_W = (0.5, 0.3, 0.2)                      # korelasi, arah tepi, tekstur
SEARCH_MARGIN = 6                               # toleransi geser per wilayah (piksel pada 128x144)
EMB_ANCHORS = [(-1.0, 0.0), (0.0, 0.0), (0.2, 20.0), (0.363, 50.0), (0.5, 75.0), (0.7, 92.0), (1.0, 100.0)]
MAX_PHOTOS = 10
NO_DETECTOR_MSG = ("Detektor wajah tidak tersedia: OpenCV versi ini tidak menyertakan cascade Haar (OpenCV 5). "
                   "Pasang opencv-python 4.x (pip install \"opencv-python>=4.8,<5\") atau letakkan model "
                   "face_detection_yunet_2023mar.onnx dan face_recognition_sface_2021dec.onnx di folder model.")


def _lin(x: float, lo: float, hi: float) -> float:
    return max(0.0, min(1.0, (x - lo) / (hi - lo)))


def _interp(x: float, anchors) -> float:
    for (x0, y0), (x1, y1) in zip(anchors, anchors[1:]):
        if x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0) if x1 > x0 else y1
    return anchors[-1][1]


def fmt_pct(v: float) -> str:
    return f"{v:.1f}".replace(".", ",") + "%"


def fmt_num(v: float, d: int = 2) -> str:
    return f"{v:.{d}f}".replace(".", ",")


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _imread(path: str):
    """Baca gambar (aman untuk path Unicode, read-only). Kembalikan (gambar, skala_terhadap_asli)."""
    import cv2
    import numpy as np
    data = np.fromfile(path, dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if img is None:
        return None, 1.0
    scale = 1.0
    if max(img.shape[:2]) > 1280:
        scale = 1280 / max(img.shape[:2])
        img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    return img, scale


def _align(img, el, er):
    """Luruskan & skalakan agar kedua mata jatuh di posisi baku (transformasi kemiripan 2 titik)."""
    import cv2
    import numpy as np
    (lx, ly), (rx, ry) = el, er
    dist = math.hypot(rx - lx, ry - ly)
    if dist < 4:
        raise ValueError("jarak mata terlalu kecil")
    ang = math.atan2(ry - ly, rx - lx)
    s = (EYE_R[0] - EYE_L[0]) / dist
    c, si = math.cos(-ang) * s, math.sin(-ang) * s
    R = np.array([[c, -si], [si, c]])
    t = np.array(EYE_L) - R @ np.array([lx, ly])
    M = np.hstack([R, t[:, None]]).astype(np.float32)
    return cv2.warpAffine(img, M, (FACE_W, FACE_H), flags=cv2.INTER_AREA if s < 1 else cv2.INTER_LINEAR,
                          borderMode=cv2.BORDER_REFLECT)


def _lbp(g):
    import numpy as np
    g = g.astype(np.int16)
    c = g[1:-1, 1:-1]
    code = np.zeros(c.shape, np.uint8)
    for bit, (dy, dx) in enumerate([(-1, -1), (-1, 0), (-1, 1), (0, 1), (1, 1), (1, 0), (1, -1), (0, -1)]):
        code |= ((g[1 + dy:g.shape[0] - 1 + dy, 1 + dx:g.shape[1] - 1 + dx] >= c).astype(np.uint8) << bit)
    return code


def _prep(aligned_bgr) -> dict:
    """Normalisasi pencahayaan + peta fitur untuk perbandingan."""
    import cv2
    import numpy as np
    g = cv2.cvtColor(aligned_bgr, cv2.COLOR_BGR2GRAY)
    g = cv2.createCLAHE(2.0, (4, 4)).apply(g)
    gf = g.astype(np.float32)
    d = gf - cv2.GaussianBlur(gf, (0, 0), 6)
    ln = d / (np.sqrt(cv2.GaussianBlur(d * d, (0, 0), 10)) + 4.0)
    sm = cv2.GaussianBlur(gf, (0, 0), 1.0)
    gx, gy = cv2.Sobel(sm, cv2.CV_32F, 1, 0), cv2.Sobel(sm, cv2.CV_32F, 0, 1)
    lbp_src = cv2.GaussianBlur(g, (0, 0), 1.3)            # redam derau/blur agar tekstur lebih stabil
    return {"ln": ln, "lbp": _lbp(lbp_src), "mag": np.hypot(gx, gy), "ori": np.arctan2(gy, gx) % math.pi}


def _cells(x0, y0, x1, y1):
    mx, my = (x0 + x1) // 2, (y0 + y1) // 2
    return [(x0, y0, mx, my), (mx, y0, x1, my), (x0, my, mx, y1), (mx, my, x1, y1)]


def _region_metrics(pa: dict, pb: dict, rect) -> tuple[float, float, float, tuple[int, int]]:
    import cv2
    import numpy as np
    x0, y0, x1, y1 = rect
    ix0, iy0, ix1, iy1 = x0 + 4, y0 + 4, x1 - 4, y1 - 4
    m = SEARCH_MARGIN
    H, W = pb["ln"].shape
    px0, py0, px1, py1 = max(ix0 - m, 0), max(iy0 - m, 0), min(ix1 + m, W), min(iy1 + m, H)
    res = cv2.matchTemplate(pb["ln"][py0:py1, px0:px1].astype(np.float32),
                            pa["ln"][iy0:iy1, ix0:ix1].astype(np.float32), cv2.TM_CCOEFF_NORMED)
    _, ncc, _, loc = cv2.minMaxLoc(res)
    shift = (int(loc[0] + px0 - ix0), int(loc[1] + py0 - iy0))
    inter = []
    for (a, b, c, d) in _cells(x0, y0, x1, y1):
        sl = (slice(max(b - 1, 0), d - 1), slice(max(a - 1, 0), c - 1))
        ha = np.bincount(pa["lbp"][sl].ravel(), minlength=256).astype(np.float32)
        hb = np.bincount(pb["lbp"][sl].ravel(), minlength=256).astype(np.float32)
        inter.append(float(np.minimum(ha / max(ha.sum(), 1), hb / max(hb.sum(), 1)).sum()))
    vs = []
    for P in (pa, pb):
        v = []
        for (a, b, c, d) in _cells(x0, y0, x1, y1):
            o, mg = P["ori"][b:d, a:c].ravel(), P["mag"][b:d, a:c].ravel()
            hh = np.bincount(np.minimum((o / math.pi * 9).astype(int), 8), weights=mg, minlength=9)
            v.append(hh / (np.linalg.norm(hh) + 1e-6))
        vs.append(np.concatenate(v))
    hog = float(vs[0] @ vs[1] / (np.linalg.norm(vs[0]) * np.linalg.norm(vs[1]) + 1e-6))
    return float(ncc), hog, float(np.mean(inter)), shift


class FacePhoto:
    def __init__(self, path: str):
        self.path, self.name = str(path), os.path.basename(str(path))
        self.sha256, self.ok, self.note = "", False, ""
        self.n_faces, self.box, self.el, self.er = 0, None, None, None
        self.eye_method, self.q = "-", {}
        self.img = self.aligned = self.prep = self.emb = None
        self.scale = 1.0

    def public(self) -> dict:
        return {"path": self.path, "name": self.name, "sha256": self.sha256, "ok": self.ok, "note": self.note,
                "wajah_terdeteksi": self.n_faces, "metode_mata": self.eye_method, "kualitas": self.q}


class FaceComparer:
    DET = "face_detection_yunet_2023mar.onnx"
    REC = "face_recognition_sface_2021dec.onnx"

    def __init__(self, model_dir: Optional[Path] = None):
        import cv2
        self.cv2 = cv2
        self._face, self._eye, self._eyeg = [], None, None
        if hasattr(cv2, "CascadeClassifier") and hasattr(cv2, "data"):          # OpenCV 4.x
            hc = cv2.data.haarcascades
            self._face = [cv2.CascadeClassifier(hc + "haarcascade_frontalface_alt2.xml"),
                          cv2.CascadeClassifier(hc + "haarcascade_frontalface_default.xml")]
            self._eye = cv2.CascadeClassifier(hc + "haarcascade_eye.xml")
            self._eyeg = cv2.CascadeClassifier(hc + "haarcascade_eye_tree_eyeglasses.xml")
            if any(c.empty() for c in self._face):
                self._face = []
        self.mode, self.note = "fitur", ""
        md = Path(model_dir) if model_dir else None
        if md and (md / self.DET).exists() and (md / self.REC).exists():
            try:
                self._det = cv2.FaceDetectorYN.create(str(md / self.DET), "", (320, 320), 0.8, 0.3, 5000)
                self._rec = cv2.FaceRecognizerSF.create(str(md / self.REC), "")
                self.mode = "sface"
            except Exception as e:                                   # noqa: BLE001
                self.note = f"Model SFace gagal dimuat ({type(e).__name__}); memakai analisis fitur."

    @property
    def detector_available(self) -> bool:
        return self.mode == "sface" or bool(self._face)

    @property
    def label(self) -> str:
        return "SFace (jaringan saraf) + analisis fitur wilayah" if self.mode == "sface" else "Analisis fitur wilayah wajah (OpenCV, tanpa jaringan saraf)"

    # ------------------------------------------------------------- analisis satu foto
    def _boxes(self, gray) -> list:
        for c in self._face:
            b = c.detectMultiScale(gray, 1.1, 5, minSize=(40, 40))
            if len(b):
                return sorted(((int(x), int(y), int(w), int(h)) for x, y, w, h in b), key=lambda r: -r[2] * r[3])
        return []

    def _eyes(self, gray, box):
        x, y, w, h = box
        y0, y1 = y + int(h * 0.15), y + int(h * 0.62)
        roi = gray[y0:y1, x:x + w]
        cands = []
        side = lambda c: ([k for k in c if k[0] < 0.5], [k for k in c if k[0] >= 0.5])
        if self._eye is not None and roi.size:
            for casc, sf, mn in ((self._eye, 1.1, 4), (self._eye, 1.05, 3), (self._eyeg, 1.05, 3)):
                ms = max(10, w // 12)
                for (a, b, cw, ch) in casc.detectMultiScale(roi, sf, mn, minSize=(ms, ms), maxSize=(w // 3, w // 3)):
                    cx, cy = (a + cw / 2) / w, (b + y0 - y + ch / 2) / h
                    if 0.12 < cx < 0.88 and 0.22 < cy < 0.56:
                        cands.append((cx, cy))
                if all(side(cands)):
                    break
        L, R = side(cands)
        near = lambda c, px: min(c, key=lambda k: (k[0] - px) ** 2 + (k[1] - 0.38) ** 2)
        if L and R:
            l, r, method = near(L, 0.30), near(R, 0.70), "terdeteksi"
        elif L or R:
            e = near(L, 0.30) if L else near(R, 0.70)
            l, r = (e, (1 - e[0], e[1])) if L else ((1 - e[0], e[1]), e)
            method = "sebagian (satu mata terdeteksi, satunya diperkirakan)"
        else:
            l, r, method = (0.30, 0.38), (0.70, 0.38), "diperkirakan dari proporsi wajah"
        return (x + l[0] * w, y + l[1] * h), (x + r[0] * w, y + r[1] * h), method

    def analyze(self, path: str) -> FacePhoto:
        cv2 = self.cv2
        ph = FacePhoto(path)
        try:
            ph.sha256 = file_sha256(path)
            img, ph.scale = _imread(path)
        except OSError as e:
            ph.note = f"Berkas tidak dapat dibaca: {e.strerror or e}"
            return ph
        if img is None:
            ph.note = "Berkas bukan gambar yang dapat dibaca"
            return ph
        ph.img = img
        if not self.detector_available and type(self)._boxes is FaceComparer._boxes:
            ph.note = NO_DETECTOR_MSG
            return ph
        gray = cv2.equalizeHist(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY))
        boxes, sf_face = self._boxes(gray), None
        if self.mode == "sface":
            try:
                h, w = img.shape[:2]
                self._det.setInputSize((w, h))
                _, fs = self._det.detect(img)
                if fs is not None and len(fs):
                    sf_face = max(fs, key=lambda f: f[2] * f[3])
                    boxes = [(int(sf_face[0]), int(sf_face[1]), int(sf_face[2]), int(sf_face[3]))] + [b for b in boxes[1:]]
            except Exception:                                         # noqa: BLE001
                sf_face = None
        if not boxes:
            ph.note = "Tidak ada wajah terdeteksi. Gunakan foto wajah yang menghadap depan, jelas, dan cukup besar."
            return ph
        ph.n_faces, ph.box = len(boxes), boxes[0]
        x, y, w, h = ph.box
        if sf_face is not None:
            pts = sorted([(float(sf_face[4]), float(sf_face[5])), (float(sf_face[6]), float(sf_face[7]))])
            ph.el, ph.er, ph.eye_method = pts[0], pts[1], "terdeteksi"
            try:
                ph.emb = self._rec.feature(self._rec.alignCrop(img, sf_face))
            except Exception:                                         # noqa: BLE001
                ph.emb = None
        else:
            ph.el, ph.er, ph.eye_method = self._eyes(gray, ph.box)
        try:
            ph.aligned = _align(img, ph.el, ph.er)
        except ValueError:
            ph.note = "Posisi mata tidak valid; penyelarasan wajah gagal."
            return ph
        ph.prep = _prep(ph.aligned)
        g = cv2.cvtColor(ph.aligned, cv2.COLOR_BGR2GRAY)
        q = {"lebar_wajah_px": int(round(w / ph.scale)), "ketajaman": round(float(cv2.Laplacian(g, cv2.CV_64F).var()), 1),
             "kecerahan": round(float(g.mean()), 1), "kontras": round(float(g.std()), 1)}
        if ph.eye_method.startswith("terdeteksi"):
            q["kemiringan_derajat"] = round(float(math.degrees(math.atan2(ph.er[1] - ph.el[1], ph.er[0] - ph.el[0]))), 1)
            q["rasio_jarak_mata"] = round(float(math.hypot(ph.er[0] - ph.el[0], ph.er[1] - ph.el[1]) / w), 3)
            q["tinggi_mata"] = round(float(((ph.el[1] + ph.er[1]) / 2 - y) / h), 3)
        ph.q, ph.ok = q, True
        return ph

    # ------------------------------------------------------------- perbandingan sepasang foto
    def compare(self, A: FacePhoto, B: FacePhoto, ia: int, ib: int) -> dict:
        regions = []
        for name, rect, wgt in REGIONS:
            ncc, hog, lbp, shift = _region_metrics(A.prep, B.prep, rect)
            score = 100.0 * (METRIC_W[0] * _lin(ncc, *NCC_RANGE) + METRIC_W[1] * _lin(hog, *HOG_RANGE) + METRIC_W[2] * _lin(lbp, *LBP_RANGE))
            regions.append({"nama": name, "bobot": wgt, "skor": round(score, 1), "korelasi": round(ncc, 3),
                            "arah_tepi": round(hog, 3), "tekstur": round(lbp, 3), "geser": shift, "rect": rect})
        reg_score = sum(r["bobot"] * r["skor"] for r in regions)

        geo, geo_score = [], None
        if A.eye_method.startswith("terdeteksi") and B.eye_method.startswith("terdeteksi"):
            for label, key in (("Jarak antar mata ÷ lebar wajah", "rasio_jarak_mata"), ("Tinggi posisi mata dalam wajah", "tinggi_mata")):
                a, b = A.q[key], B.q[key]
                geo.append({"nama": label, "a": a, "b": b, "selisih": round(abs(a - b), 3),
                            "skor": round(100.0 * max(0.0, 1 - abs(a - b) / 0.10), 1)})
            geo_score = sum(g["skor"] for g in geo) / len(geo)

        emb_score = cos = None
        if self.mode == "sface" and A.emb is not None and B.emb is not None:
            try:
                cos = float(self._rec.match(A.emb, B.emb, self.cv2.FaceRecognizerSF_FR_COSINE))
                emb_score = _interp(cos, EMB_ANCHORS)
            except Exception:                                         # noqa: BLE001
                emb_score = None

        if emb_score is not None:
            w = {"emb": 0.55, "reg": 0.30, "geo": 0.15} if geo_score is not None else {"emb": 0.60, "reg": 0.40}
        else:
            w = {"reg": 0.85, "geo": 0.15} if geo_score is not None else {"reg": 1.0}
        comps = []
        if "emb" in w:
            comps.append({"nama": "Kesamaan embedding wajah (SFace)", "skor": round(emb_score, 1), "bobot": w["emb"], "detail": f"cosine {fmt_num(cos, 3)}"})
        comps.append({"nama": "Kemiripan 6 wilayah wajah", "skor": round(reg_score, 1), "bobot": w["reg"], "detail": "dahi, mata, hidung, mulut, dagu"})
        if "geo" in w:
            comps.append({"nama": "Kemiripan proporsi wajah", "skor": round(geo_score, 1), "bobot": w["geo"], "detail": "jarak & tinggi mata"})
        for c in comps:
            c["poin"] = round(c["skor"] * c["bobot"], 1)
        percent = round(sum(c["poin"] for c in comps), 1)

        issues = self._issues(A, B, ia, ib)
        total_w = sum(i[0] for i in issues) + (0 if self.mode == "sface" else 1)
        conf = "Tinggi" if total_w == 0 else ("Sedang" if total_w <= 2 else "Rendah")
        verdict = ("Sangat mirip" if percent >= 85 else "Mirip" if percent >= 70 else
                   "Kemiripan sedang (tidak meyakinkan)" if percent >= 50 else "Tidak mirip")
        pair = {"a": ia, "b": ib, "percent": float(percent), "verdict": verdict, "confidence": conf, "method": self.label,
                "components": comps, "regions": [{k: v for k, v in r.items() if k != "rect"} for r in regions],
                "geometry": geo, "identical_files": A.sha256 == B.sha256}
        pair["alasan"] = self._reasons(A, B, ia, ib, pair, issues)
        pair["image_png"] = self._render(A, B, ia, ib, regions, percent)
        return pair

    def _issues(self, A, B, ia, ib) -> list[tuple[int, str]]:
        out = []
        for P, i in ((A, ia), (B, ib)):
            n = f"Foto {i + 1}"
            if P.q["lebar_wajah_px"] < 50:
                out.append((3, f"{n}: wajah sangat kecil ({P.q['lebar_wajah_px']} px); detail halus hilang"))
            elif P.q["lebar_wajah_px"] < 90:
                out.append((2, f"{n}: wajah kecil ({P.q['lebar_wajah_px']} px); detail terbatas"))
            if P.q["ketajaman"] < 25:
                out.append((2, f"{n}: gambar buram (indeks ketajaman {fmt_num(P.q['ketajaman'], 0)}); tekstur wajah tidak jelas"))
            if P.q["kecerahan"] < 60 or P.q["kecerahan"] > 200:
                out.append((1, f"{n}: pencahayaan ekstrem (kecerahan {fmt_num(P.q['kecerahan'], 0)}/255)"))
            if P.eye_method.startswith("sebagian"):
                out.append((2, f"{n}: hanya satu mata terdeteksi, posisi mata lain diperkirakan; penyelarasan kurang presisi"))
            elif P.eye_method.startswith("diperkirakan"):
                out.append((3, f"{n}: mata tidak terdeteksi, penyelarasan memakai proporsi umum wajah; hasil kurang andal"))
            if abs(P.q.get("kemiringan_derajat", 0)) > 15:
                out.append((1, f"{n}: kepala miring {fmt_num(P.q['kemiringan_derajat'], 1)}°"))
            if P.n_faces > 1:
                out.append((1, f"{n}: {P.n_faces} wajah terdeteksi, yang terbesar yang dipakai"))
        d = abs(A.q["kecerahan"] - B.q["kecerahan"])
        if d > 45:
            out.append((1, f"Perbedaan pencahayaan antar foto besar (kecerahan {fmt_num(A.q['kecerahan'], 0)} vs {fmt_num(B.q['kecerahan'], 0)})"))
        r = max(A.q["lebar_wajah_px"], B.q["lebar_wajah_px"]) / max(1, min(A.q["lebar_wajah_px"], B.q["lebar_wajah_px"]))
        if r > 2.5:
            out.append((1, f"Ukuran wajah sangat berbeda antar foto ({A.q['lebar_wajah_px']} px vs {B.q['lebar_wajah_px']} px)"))
        return out

    def _reasons(self, A, B, ia, ib, pair, issues) -> list[dict]:
        regs = sorted(pair["regions"], key=lambda r: -r["skor"])
        sec = []
        head = [f"Kemiripan {fmt_pct(pair['percent'])}: {pair['verdict']}. Keyakinan analisis: {pair['confidence']}.",
                f"Metode: {pair['method']}."]
        if pair["identical_files"]:
            head.append("Kedua berkas identik (hash SHA-256 sama), jadi ini bukan perbandingan dua foto yang berbeda.")
        sec.append({"judul": "Ringkasan", "butir": head})

        sim = []
        for r in [r for r in regs if r["skor"] >= 55][:3]:
            d = "hampir identik" if r["skor"] >= 85 else "sangat serupa" if r["skor"] >= 70 else "cukup serupa"
            shift = f"; pola bergeser {r['geser'][0]},{r['geser'][1]} px (selisih posisi/sudut)" if max(abs(r["geser"][0]), abs(r["geser"][1])) >= 3 else ""
            sim.append(f"{r['nama']}: {fmt_pct(r['skor'])}, {d}. Korelasi pola {fmt_num(r['korelasi'])}, kesamaan arah tepi {fmt_num(r['arah_tepi'])}, kesamaan tekstur {fmt_num(r['tekstur'])}{shift}.")
        sec.append({"judul": "Ciri yang paling mirip", "butir": sim or ["Tidak ada wilayah wajah dengan kemiripan 55% atau lebih."]})

        dif = []
        for r in sorted([r for r in regs if r["skor"] < 60], key=lambda r: r["skor"])[:3]:
            d = "sangat berbeda" if r["skor"] < 30 else "jelas berbeda" if r["skor"] < 45 else "agak berbeda"
            dif.append(f"{r['nama']}: {fmt_pct(r['skor'])}, {d} (korelasi pola {fmt_num(r['korelasi'])}, arah tepi {fmt_num(r['arah_tepi'])}). Perbedaan di wilayah ini dapat dipengaruhi oleh {CAUSES[r['nama']]}.")
        sec.append({"judul": "Ciri yang membedakan / menurunkan nilai", "butir": dif or ["Tidak ada wilayah wajah yang jelas berbeda."]})

        sec.append({"judul": "Skor semua wilayah wajah", "butir": [
            f"{r['nama']}: {fmt_pct(r['skor'])} (bobot {int(round(r['bobot'] * 100))}%; korelasi {fmt_num(r['korelasi'])}, arah tepi {fmt_num(r['arah_tepi'])}, tekstur {fmt_num(r['tekstur'])})"
            for r in pair["regions"]]})

        geo = []
        if pair["geometry"]:
            for g in pair["geometry"]:
                geo.append(f"{g['nama']}: {fmt_num(g['a'], 3)} vs {fmt_num(g['b'], 3)} (selisih {fmt_num(g['selisih'], 3)}) -> kemiripan {fmt_pct(g['skor'])}.")
            ra, rb = A.q.get("kemiringan_derajat"), B.q.get("kemiringan_derajat")
            if ra is not None and rb is not None:
                geo.append(f"Kemiringan kepala: {fmt_num(ra, 1)}° vs {fmt_num(rb, 1)}° (selisih pose besar dapat menurunkan kemiripan meski orangnya sama).")
        else:
            geo.append("Proporsi wajah tidak dibandingkan karena kedua mata tidak terdeteksi penuh pada kedua foto, sehingga ukurannya tidak andal.")
        sec.append({"judul": "Proporsi wajah", "butir": geo})

        cond = []
        for P, i in ((A, ia), (B, ib)):
            k = "baik" if P.q["ketajaman"] >= 60 else "sedang" if P.q["ketajaman"] >= 25 else "buram"
            cond.append(f"Foto {i + 1}: wajah {P.q['lebar_wajah_px']} px, ketajaman {k} ({fmt_num(P.q['ketajaman'], 0)}), kecerahan {fmt_num(P.q['kecerahan'], 0)}/255, kontras {fmt_num(P.q['kontras'], 0)}; mata: {P.eye_method}.")
        cond += [f"{t} -> menurunkan keyakinan." for _, t in issues]
        if self.mode != "sface":
            cond.append("Metode tanpa jaringan saraf (model SFace tidak terpasang) -> keyakinan dibatasi maksimal Sedang.")
        sec.append({"judul": "Kondisi foto yang memengaruhi", "butir": cond})

        calc = [f"{c['nama']} ({c['detail']}): {fmt_pct(c['skor'])} x bobot {int(round(c['bobot'] * 100))}% = {fmt_num(c['poin'], 1)} poin." for c in pair["components"]]
        calc.append(f"Total = {fmt_pct(pair['percent'])}. Skor wilayah = 50% korelasi pola + 30% arah tepi + 20% tekstur, lalu dibobot per wilayah "
                    "(hidung 20%, mulut 18%, mata 17% + 17%, dagu 16%, dahi 12%).")
        sec.append({"judul": "Cara nilai dihitung", "butir": calc})

        cat = ["Persentase adalah skor kemiripan visual relatif, BUKAN probabilitas bahwa kedua foto adalah orang yang sama.",
               "Pose, ekspresi, usia, penutup wajah, dan kualitas foto dapat menurunkan skor orang yang sama atau menaikkan skor orang yang mirip.",
               "Hasil wajib diverifikasi pemeriksa manusia dan tidak boleh menjadi satu-satunya dasar identifikasi."]
        if self.mode != "sface":
            cat.insert(1, "Pemetaan skor bersifat heuristik dan belum dikalibrasi dengan dataset wajah berlabel besar. Pasang model SFace untuk hasil lebih andal.")
        sec.append({"judul": "Catatan kehati-hatian", "butir": cat})
        return sec

    # ------------------------------------------------------------- citra anotasi
    def _render(self, A, B, ia, ib, regions, percent) -> bytes:
        import numpy as np
        cv2 = self.cv2
        colw, toph, both, hdr, ftr = 440, 280, 340, 36, 30
        canvas = np.full((hdr + toph + both + ftr, colw * 2, 3), 245, np.uint8)
        put = lambda im, t, x, y, s=0.5, c=(40, 40, 40), th=1: cv2.putText(im, t, (x, y), cv2.FONT_HERSHEY_SIMPLEX, s, c, th, cv2.LINE_AA)
        put(canvas, f"Foto {ia + 1}", 12, 24, 0.7, (30, 30, 30), 2)
        put(canvas, f"Foto {ib + 1}", colw + 12, 24, 0.7, (30, 30, 30), 2)
        put(canvas, f"Kemiripan {percent:.1f}%".replace(".", ","), colw * 2 - 215, 24, 0.7, (150, 40, 20), 2)
        for k, P in enumerate((A, B)):
            im = P.img.copy()
            x, y, w, h = P.box
            t = max(2, im.shape[1] // 250)
            cv2.rectangle(im, (x, y), (x + w, y + h), (0, 200, 0), t)
            ec = (0, 200, 0) if P.eye_method.startswith("terdeteksi") else (0, 140, 255)
            for e in (P.el, P.er):
                cv2.circle(im, (int(e[0]), int(e[1])), max(3, w // 22), ec, t)
            s = min((colw - 20) / im.shape[1], (toph - 10) / im.shape[0])
            im = cv2.resize(im, None, fx=s, fy=s, interpolation=cv2.INTER_AREA)
            ox, oy = k * colw + (colw - im.shape[1]) // 2, hdr + (toph - im.shape[0]) // 2
            canvas[oy:oy + im.shape[0], ox:ox + im.shape[1]] = im
            al = cv2.resize(P.aligned, None, fx=2.2, fy=2.2, interpolation=cv2.INTER_CUBIC)
            ax, ay = k * colw + (colw - al.shape[1]) // 2, hdr + toph + 6
            canvas[ay:ay + al.shape[0], ax:ax + al.shape[1]] = al
            for r in regions:
                x0, y0, x1, y1 = [int(v * 2.2) for v in r["rect"]]
                col = (60, 170, 60) if r["skor"] >= 70 else (0, 190, 230) if r["skor"] >= 50 else (60, 60, 220)
                cv2.rectangle(canvas, (ax + x0, ay + y0), (ax + x1, ay + y1), col, 1)
                put(canvas, f"{SHORT[r['nama']]} {r['skor']:.0f}%", ax + x0 + 2, ay + y0 + 12, 0.36, col, 1)
        put(canvas, "Kotak hijau=wajah; lingkaran hijau=mata terdeteksi, oranye=diperkirakan. Wilayah: hijau>=70, kuning 50-69, merah<50",
            8, hdr + toph + both + 20, 0.38, (90, 90, 90))
        ok, buf = cv2.imencode(".png", canvas)
        return bytes(buf) if ok else b""


# ----------------------------------------------------------------------------
# Teks penjelasan (dipakai GUI & PDF)
# ----------------------------------------------------------------------------

def format_pair_text(pair: dict, photos: list[dict]) -> str:
    a, b = photos[pair["a"]], photos[pair["b"]]
    lines = [f"FOTO {pair['a'] + 1} vs FOTO {pair['b'] + 1}",
             f"  Foto {pair['a'] + 1}: {a['name']}", f"  Foto {pair['b'] + 1}: {b['name']}", ""]
    for s in pair["alasan"]:
        lines.append(s["judul"].upper())
        lines += [f"  - {x}" for x in s["butir"]]
        lines.append("")
    return "\n".join(lines).rstrip()
