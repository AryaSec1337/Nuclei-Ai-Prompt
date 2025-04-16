# 🔍 Nuclei Prompt Scanner

![image](https://github.com/user-attachments/assets/87fe13e4-b488-4a32-9b78-733fbcc2ec57)


**Nuclei Prompt Scanner** adalah tools berbasis Python yang memanfaatkan **Nuclei** dan **AI Prompting** untuk melakukan pemindaian kerentanan pada web target berdasarkan kategori OWASP dan lainnya, dengan antarmuka interaktif berbasis CLI (command-line).

## ✨ Fitur Utama

- ✅ Interaktif & mudah digunakan
- 🤖 Ditenagai AI Prompt untuk eksplorasi kerentanan yang lebih luas
- 📋 Mendukung lebih dari 15+ kategori seperti XSS, SQLi, RCE, LFI, IDOR, dll.
- 🎨 Output berwarna menggunakan `rich` agar lebih enak dibaca
- 📝 Log hasil scan ke file secara otomatis
- 💾 Output JSON tersimpan dalam folder `output-json/`

## 🧠 Daftar Kategori yang Didukung

Beberapa kategori yang tersedia:
- Authentication Bypass
- Broken Access Control
- Command Injection
- LFI/RFI
- XSS (Cross-Site Scripting)
- SQL Injection
- SSRF
- Security Misconfiguration
- ...dan banyak lagi!

Kamu juga bisa memilih opsi **99** untuk melakukan scan di semua kategori sekaligus.

## 🚀 Cara Penggunaan

### 1. Install dependencies:

```bash
pip install -r requirements.txt
```

### 2. Install Nuclei
```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 3. Usage
```
python nuclei_prompt.py
```
Ikuti instruksi pada CLI untuk:

- Memasukkan domain target
- Memilih kategori scan

📦 Contoh Output
✅ Kerentanan ditemukan:
```
Issue     : sql-injection-basic
Category  : SQL Injection
Severity  : critical
URL       : https://target.com/vuln.php?id=1
```
📁 Output
- Semua hasil scan akan disimpan di file log scan_result_YYYYMMDD-HHMMSS.log
- Output JSON akan disimpan di direktori output-json/

👨‍💻 Author
AryaSec1337
- Twitter  : @AryaSec1337
- GitHub   : github.com/aryasec1337
- Discord  : https://discord.gg/PBErEYS7

⚠️ Disclaimer
Tools ini hanya untuk tujuan edukasi dan pengujian legal. Jangan digunakan untuk melakukan tindakan ilegal terhadap sistem yang tidak kamu miliki izin untuk mengujinya.

