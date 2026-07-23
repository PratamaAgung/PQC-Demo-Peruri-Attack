# 🔓 Digital Signature Attack Demo

Demo webapp yang menunjukkan bagaimana digital signature berbasis RSA-64bit (toy) dapat di-break menggunakan simulasi **Shor's Algorithm**. Tujuannya adalah untuk mengilustrasikan pentingnya **Post-Quantum Cryptography (PQC)**.

> ⚠️ **EDUCATIONAL PURPOSE ONLY** — Demo ini menggunakan RSA-64bit yang sengaja dibuat lemah. RSA sesungguhnya menggunakan key 2048+ bit yang tidak rentan terhadap komputer klasik.

## Prasyarat

- **Node.js** >= 16.x
- **npm** >= 8.x

## Quick Start

```bash
# Clone / masuk ke directory project
cd "PQC Demo Peruri Attack"

# Install dependencies & jalankan server
./start.sh
```

Atau secara manual:

```bash
npm install
npm start
```

Buka browser di **http://localhost:3000**

## Flow Attack

```
┌─────────────────────────────────────────────────────────────┐
│  Step 0: Generate Sample Signed PDF (toy RSA-64bit)         │
├─────────────────────────────────────────────────────────────┤
│  Step 1: Hacker upload PDF yang sudah di-sign               │
├─────────────────────────────────────────────────────────────┤
│  Step 2: Locate public key dari certificate dalam PDF       │
│          $ LC_ALL=C sed -n '/BEGIN CERT/,/END CERT/p' file.pdf │
├─────────────────────────────────────────────────────────────┤
│  Step 3: Jalankan Shor's Algorithm                          │
│          → Faktorkan N = p × q                              │
│          → Hitung φ(N) = (p-1)(q-1)                         │
│          → Derive private key: d = e⁻¹ mod φ(N)            │
├─────────────────────────────────────────────────────────────┤
│  Step 4: Upload dokumen baru → Sign dengan private key      │
│          yang sudah di-crack → Download forged document      │
└─────────────────────────────────────────────────────────────┘
```

## Teknologi

| Komponen | Detail |
|----------|--------|
| Backend | Node.js + Express |
| Frontend | Vanilla HTML/CSS/JS (single page) |
| PDF | pdf-lib (generate PDF) |
| Crypto | Toy RSA-64bit (custom implementation) |
| Attack | Shor's Algorithm (simulated via Pollard's Rho) |

## Struktur Project

```
.
├── README.md           # Dokumentasi ini
├── start.sh            # Startup script
├── package.json        # Dependencies
├── server.js           # Express server + RSA + Shor's simulation
├── public/
│   └── index.html      # Frontend UI
└── uploads/            # (auto-created) file uploads
```

## Penjelasan Teknis

### Toy RSA-64bit
- Modulus N = p × q, dimana p dan q adalah prime ~32-bit
- Public exponent e = 65537 (standar)
- Private key d = e⁻¹ mod φ(N)
- Signature: `sig = hash^d mod N`
- Verify: `hash == sig^e mod N`

### Shor's Algorithm (Simulated)
Pada quantum computer sesungguhnya, Shor's Algorithm menggunakan **quantum period-finding** untuk menemukan faktor dari N secara eksponensial lebih cepat. Demo ini mensimulasikannya secara klasik menggunakan Pollard's Rho factoring untuk menunjukkan hasilnya.

### Mengapa Ini Penting?
- RSA-2048 aman dari komputer klasik, tapi **rentan terhadap quantum computer** yang cukup besar
- NIST telah menstandardisasi algoritma PQC (ML-KEM, ML-DSA, SLH-DSA) sebagai pengganti
- Demo ini menunjukkan *konsep* serangan — pada skala yang diperkecil

## API Endpoints

| Method | Path | Deskripsi |
|--------|------|-----------|
| POST | `/api/generate-signed-pdf` | Generate sample signed PDF |
| POST | `/api/upload-signed-pdf` | Upload signed PDF untuk dianalisis |
| POST | `/api/extract-public-key` | Extract certificate/public key |
| POST | `/api/shor-attack` | Jalankan Shor's Algorithm |
| POST | `/api/sign-document` | Sign dokumen dengan cracked key |
| GET | `/api/download/:filename` | Download file |

## License

Educational use only. Not for production or malicious purposes.
