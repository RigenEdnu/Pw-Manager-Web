<h1>Website Password Manager</h1>

<div align="center">
  <img src="public/img/logo-200.png" alt="Logo" width="200" />
</div>

Website Password Manager adalah aplikasi berbasis web yang dirancang untuk membantu pengguna menyimpan, mengelola, dan mengamankan kata sandi mereka dengan mudah. Dibangun menggunakan Python (Flask) sebagai backend dan JSON sebagai basis data, aplikasi ini menerapkan teknik hashing untuk melindungi password pengguna dan enkripsi untuk data password yang disimpan.

Fitur Utama
Manajemen Password:
- Tambah, lihat, ubah, dan hapus (CRUD) data password.
- Enkripsi data password yang disimpan untuk keamanan tambahan.
Generate Password:
- Menghasilkan password acak yang kuat sesuai kriteria pengguna.
Keamanan:
- Password pengguna di-hash menggunakan algoritma SHA-256.
- Autentikasi pengguna untuk memastikan hanya pengguna terotorisasi yang dapat mengakses   data.
Antarmuka Pengguna:
- Ramah pengguna dan responsif.

Teknologi yang Digunakan:
- Backend: Python (Flask)
- Basis Data: JSON
- Keamanan: Hashing (SHA-256), Enkripsi (cryptography.fernet)
- Frontend: HTML, CSS, JavaScript

Cara Menjalankan Password Manager
- Python 3.x 
- Pip (Python package manager)

Langkah-langkah
Clone Repository:
- git clone https://github.com/RigenEdnu/Pw-Manager-Web.git
- cd Pw-Manager-Web

Instal Dependensi:
- pip install -r requirements.txt

Jalankan Aplikasi:
- python app.py
Akses Aplikasi:
- Buka browser dan akses http://127.0.0.1:5000

Tim Pengembang
- Nikolas Gilarso Putra (24.01.5113)
- Rigen Ednu Prayudha (24.01.5119)
- Chrisantos Seftrian Enol (24.01.5135)
