# EAGLE

**Forensic Triage & OSINT Platform**: triase barang bukti digital, dari akuisisi sampai Berita Acara.

Aplikasi desktop (Python + tkinter) untuk triase barang bukti digital.

## Mulai cepat
```
pip install -r requirements.txt          # Linux: sudo apt install python3-tk
python eagle.py                     # instalasi baru: klik "Setup awal: buat Admin pertama" (OTP pertama ditampilkan)
```
Setelah itu Admin memakai **Dashboard Admin** (tab A) untuk membuat pengguna dan menerbitkan OTP.
Alternatif baris perintah: `python admin_console.py add-user|issue-otp|recovery-code|reset-password|disable|enable|unlock|list|verify-audit`.

## OTP tanpa terminal
- **Minta OTP ke Admin** (layar login): penyidik melihat *kode verifikasi* 6 digit dan menyebutkannya ke Admin; Admin menyetujui di
  Dashboard > Permintaan OTP dengan mengetik kode itu; OTP otomatis terisi di layar penyidik. OTP dikirim terenkripsi (kunci turunan
  kode verifikasi), baca-sekali, tidak pernah tersimpan sebagai teks biasa. Syarat: Admin & penyidik berbagi `FORENSIC_HOME` (folder jaringan/server lokal).
- **Kode pemulihan Admin** (break-glass): dibuat saat Setup awal / tombol di Ringkasan; dipakai dari layar login > Pemulihan Admin bila semua Admin
  terkunci atau lupa sandi. Sekali pakai (dirotasi), dibatasi 5x salah, hanya Admin aktif, tercatat & muncul sebagai peringatan di dashboard.
  Siapa pun yang memegang kode + akses ke mesin data menguasai akun Admin: simpan seperti kunci brankas.

## Dashboard Admin (tab A, hanya peran admin)
Ringkasan (login sukses/gagal, akun terkunci, OTP aktif, aktivitas, status rantai log, peringatan login gagal berulang),
Pengguna (tambah, reset sandi, buka kunci, nonaktifkan, ubah peran, hapus), Terbitkan OTP (tampil sekali, tidak tersimpan, bisa dicabut),
Aktivitas & Audit (filter + ekspor CSV aman dari formula-injection). Hak akses ditegakkan di `AdminService` (dicek ulang tiap operasi),
dengan pengaman: tidak bisa menghapus/menonaktifkan/menurunkan diri sendiri atau Admin aktif terakhir. Penyidik hanya melihat log miliknya sendiri.
Opsional: `export GEMINI_API_KEY=...` (atau isi di tab "AI & Laporan"), `FORENSIC_HOME` (lokasi data),
`FORENSIC_MODELS` (folder model wajah), `GEMINI_MODEL` (default gemini-2.5-flash; ganti bila model dipensiunkan).

## Fitur -> berkas
| Fitur | Implementasi |
|---|---|
| Login berlapis + OTP Komandan | `AuthStore`: PBKDF2-SHA256 600k, OTP acak 8 digit disimpan sebagai hash, sekali pakai, kedaluwarsa, terikat user, kunci akun 5x gagal, auto-logout 15 menit |
| Akuisisi read-only + MD5/SHA-256 | `acquire_file`: mode `rb` (+`O_NOATIME` bila bisa), streaming, deteksi berkas berubah saat dibaca, `reverify` |
| Chain of Custody | `AuditLog`: JSONL berantai-hash; ubah satu baris -> terdeteksi |
| Bitcoin & email | Regex + **validasi checksum** Base58Check/Bech32/Bech32m (nol false-positive dari string acak), dukung UTF-16 |
| Anomali berkas | Magic-bytes vs ekstensi, ekstensi ganda, trik RLO U+202E, entropi tinggi |
| GPS EXIF + peta | Peta Leaflet (browser), plot offline di aplikasi, ekspor KML |
| Pengenal Wajah | Bandingkan 2-10 foto: persentase kemiripan + alasan terukur (6 wilayah wajah, proporsi, kualitas foto, rincian hitung) + citra anotasi; SFace bila model ada, jika tidak analisis fitur (OpenCV 4.x) |
| Gemini + PDF | REST tanpa SDK; hanya ringkasan terstruktur & tersamar dikirim; fallback ringkasan lokal; PDF via reportlab |

## Keterbatasan yang ditemukan saat membangun, dan penanganannya
| Temuan | Penanganan di versi ini |
|---|---|
| Tak ada pyotp / SDK Gemini / face_recognition / pustaka peta | Diganti implementasi stdlib, REST, OpenCV, dan Leaflet+plot offline |
| Tak ada jaringan -> Gemini & tile peta bisa gagal | Fallback otomatis ke ringkasan lokal; peta menampilkan tabel koordinat |
| Regex dompet mentah banyak salah-positif | Validasi checksum |
| Nama berkas ikut bocor ke AI lewat teks alasan anomali (ditemukan uji) | Disamarkan |
| Karakter bidi di nama berkas jadi kotak hitam di PDF (ditemukan uji) | Ditampilkan sebagai `[U+202E]` |

## Batasan yang HARUS Anda ketahui
1. **GUI belum pernah dijalankan secara visual** di lingkungan pembuatan (tanpa tkinter/display). Logikanya diuji penuh
   (`selftest.py`, 139 uji) dan alur GUI di-smoke-test dengan widget tiruan (`selftest_gui.py`), tetapi tata letak perlu dicek di mesin Anda.
2. **Deteksi wajah butuh OpenCV 4.x (Haar) atau model YuNet/SFace.** OpenCV 5 tidak menyertakan Haar; aplikasi memberi pesan jelas, tidak crash. Uji pipeline dijalankan dengan koordinat deteksi terskrip pada foto nyata (deteksi langsung teruji pada OpenCV 4.13 saat pengembangan). **Skor wajah mode fallback** dan ambangnya belum dikalibrasi dengan data nyata. Perlakukan sebagai peringkat kandidat;
   untuk hasil layak, taruh `face_detection_yunet_2023mar.onnx` dan `face_recognition_sface_2021dec.onnx` (OpenCV Zoo) di `FORENSIC_MODELS`.
   Jalur SFace belum teruji di sini (tak ada model). Hasil wajah tidak boleh menjadi satu-satunya dasar identifikasi.
3. **Read-only tingkat perangkat lunak.** Untuk pembuktian di pengadilan gunakan write-blocker perangkat keras / salinan image, bukan media asli langsung.
4. **OTP berbasis berkas**: Admin dan aplikasi harus berbagi `FORENSIC_HOME` (mis. folder terlindungi). Untuk banyak mesin, ganti `AuthStore` dengan layanan server.
   Log audit berantai-hash mendeteksi perubahan, tetapi tidak mencegah penghapusan total; ekspor/arsipkan berkala.
5. **Panggilan Gemini langsung belum diuji** (tanpa internet saat pembuatan; hanya jalur galat & fallback yang teruji). Mengirim data ke pihak ketiga
   tunduk pada kebijakan institusi Anda - pertahankan opsi "Samarkan".
6. Templat Berita Acara bersifat generik; sesuaikan redaksi dengan format resmi dan ketentuan hukum institusi/yurisdiksi Anda.
