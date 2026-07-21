const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const forge = require('node-forge');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');

const app = express();
const PORT = 3000;

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ============================================================
// TOY RSA-64bit Implementation
// ============================================================

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b > 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

function modInverse(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) return null;
  return ((old_s % m) + m) % m;
}

function toyRSASign(hashBigInt, privateKey) {
  return modPow(hashBigInt, privateKey.d, privateKey.n);
}

function toyRSAVerify(hashBigInt, signature, publicKey) {
  const decrypted = modPow(signature, publicKey.e, publicKey.n);
  return decrypted === hashBigInt;
}

// ============================================================
// Shor's Algorithm Simulation (Classical factoring for demo)
// ============================================================

function shorsAlgorithm(n) {
  const steps = [];
  steps.push(`Target modulus N = ${n}`);
  steps.push(`Step 1: Choose random a where 1 < a < N`);
  
  const nBig = BigInt(n);
  
  steps.push(`Step 2: Using quantum period-finding (simulated)...`);
  steps.push(`Step 3: Finding period r of f(x) = a^x mod N`);
  
  const factors = pollardRho(nBig);
  if (factors) {
    steps.push(`Step 4: Period found! Computing gcd(a^(r/2) ± 1, N)`);
    steps.push(`Step 5: Factors discovered: p = ${factors.p}, q = ${factors.q}`);
    steps.push(`✓ Factorization successful: ${n} = ${factors.p} × ${factors.q}`);
    return { success: true, p: factors.p, q: factors.q, steps };
  }
  
  steps.push(`✗ Factorization failed`);
  return { success: false, steps };
}

function pollardRho(n) {
  if (n % 2n === 0n) return { p: 2n, q: n / 2n };
  
  let x = 2n;
  let y = 2n;
  let c = 1n;
  let d = 1n;
  
  const f = (x) => (x * x + c) % n;
  
  while (d === 1n) {
    x = f(x);
    y = f(f(y));
    d = gcd(x > y ? x - y : y - x, n);
  }
  
  if (d !== n) {
    return { p: d, q: n / d };
  }
  
  // Fallback: trial division for small numbers
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) {
      return { p: i, q: n / i };
    }
  }
  return null;
}

// ============================================================
// X.509 Certificate Parsing
// ============================================================

function parseX509CertPEM(pem) {
  try {
    const cert = forge.pki.certificateFromPem(pem);
    const publicKey = cert.publicKey;
    const n = BigInt('0x' + publicKey.n.toString(16));
    const e = BigInt('0x' + publicKey.e.toString(16));
    
    return {
      n,
      e,
      subject: cert.subject.getField('CN') ? cert.subject.getField('CN').value : 'Unknown',
      issuer: cert.issuer.getField('CN') ? cert.issuer.getField('CN').value : 'Unknown',
      validFrom: cert.validity.notBefore.toISOString(),
      validTo: cert.validity.notAfter.toISOString(),
      algorithm: 'RSA',
      bitLength: publicKey.n.bitLength()
    };
  } catch (err) {
    // Fallback: try parsing as JSON-encoded toy cert (backward compat)
    const lines = pem.split('\n');
    const b64 = lines.filter(l => !l.startsWith('-----')).join('');
    const data = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
    return {
      n: BigInt(data.modulus),
      e: BigInt(data.exponent),
      subject: 'Toy RSA Certificate',
      issuer: 'Toy CA',
      algorithm: 'TOY-RSA',
      bitLength: BigInt(data.modulus).toString(2).length
    };
  }
}

// ============================================================
// API Routes
// ============================================================

// Step 1: Upload signed PDF
app.post('/api/upload-signed-pdf', upload.single('pdf'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    // Read as binary buffer
    const buffer = fs.readFileSync(req.file.path);
    // Convert to latin1 for safe text pattern matching in binary PDF
    const content = buffer.toString('latin1');
    
    // Try to find X.509 certificate
    const certMatch = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    
    if (!certMatch) {
      return res.status(400).json({ 
        error: 'No digital signature certificate found in PDF. Make sure the PDF contains an embedded certificate.' 
      });
    }
    
    // Extract the PEM - since it's ASCII content within the binary, latin1 preserves it correctly
    const certPEM = certMatch[0];
    
    // Also look for PQC-SIGNATURE block
    const sigMatch = content.match(/-----BEGIN PQC-SIGNATURE-----([\s\S]*?)-----END PQC-SIGNATURE-----/);
    const signature = sigMatch ? sigMatch[1].trim() : null;
    
    // Parse the certificate to extract public key
    let publicKey;
    let certInfo;
    try {
      certInfo = parseX509CertPEM(certPEM);
      publicKey = { n: certInfo.n.toString(), e: certInfo.e.toString() };
    } catch (parseErr) {
      return res.status(400).json({ error: `Failed to parse certificate: ${parseErr.message}` });
    }
    
    res.json({
      success: true,
      filename: req.file.filename,
      certificate: certPEM,
      publicKey,
      certInfo: {
        subject: certInfo.subject,
        issuer: certInfo.issuer,
        algorithm: certInfo.algorithm,
        bitLength: certInfo.bitLength,
        validFrom: certInfo.validFrom,
        validTo: certInfo.validTo
      },
      signature
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Step 2: Extract public key (simulates sed command)
app.post('/api/extract-public-key', (req, res) => {
  const { filename } = req.body;
  const filepath = path.join(__dirname, 'uploads', filename);
  
  if (!fs.existsSync(filepath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  const buffer = fs.readFileSync(filepath);
  const content = buffer.toString('latin1');
  const certMatch = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  
  if (!certMatch) {
    return res.status(400).json({ error: 'No certificate found in file' });
  }
  
  const certPEM = certMatch[0];
  let certInfo;
  try {
    certInfo = parseX509CertPEM(certPEM);
  } catch (parseErr) {
    return res.status(400).json({ error: `Failed to parse certificate: ${parseErr.message}` });
  }
  
  const command = `sed -n '/BEGIN CERT/,/END CERT/p' ${filename}`;
  
  res.json({
    success: true,
    command,
    certificate: certPEM,
    publicKey: { n: certInfo.n.toString(), e: certInfo.e.toString() },
    certInfo: {
      subject: certInfo.subject,
      issuer: certInfo.issuer,
      algorithm: certInfo.algorithm,
      bitLength: certInfo.bitLength,
      validFrom: certInfo.validFrom,
      validTo: certInfo.validTo
    },
    modulusBits: certInfo.bitLength
  });
});

// Step 3: Run Shor's algorithm to factor N and derive private key
app.post('/api/shor-attack', (req, res) => {
  const { n, e } = req.body;
  
  const nBig = BigInt(n);
  const eBig = BigInt(e);
  
  const result = shorsAlgorithm(n);
  
  if (result.success) {
    const p = result.p;
    const q = result.q;
    const phi = (p - 1n) * (q - 1n);
    const d = modInverse(eBig, phi);
    
    res.json({
      success: true,
      steps: result.steps,
      factors: { p: p.toString(), q: q.toString() },
      privateKey: { n: nBig.toString(), e: eBig.toString(), d: d.toString() },
      message: 'Private key successfully derived from public key using Shor\'s algorithm!'
    });
  } else {
    res.status(400).json({ success: false, steps: result.steps, error: 'Failed to factor N' });
  }
});

// Step 4 & 5: Sign a new document with the cracked private key
app.post('/api/sign-document', upload.single('pdf'), async (req, res) => {
  try {
    const { n, e, d, certificate } = req.body;
    
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    const privateKey = { n: BigInt(n), e: BigInt(e), d: BigInt(d) };
    const publicKey = { n: BigInt(n), e: BigInt(e) };
    
    // Read the uploaded PDF
    const pdfBuffer = fs.readFileSync(req.file.path);
    
    // Add visual signature to the PDF (simple handwritten-style like the original)
    let stampedPdfBytes;
    try {
      const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
      const pages = pdfDoc.getPages();
      const lastPage = pages[pages.length - 1];
      const { width } = lastPage.getSize();
      
      const font = await pdfDoc.embedFont(StandardFonts.Courier);
      
      // Draw a simple signature at the bottom of the last page
      // "Signature:" label
      lastPage.drawText('Signature:', {
        x: 50,
        y: 80,
        font,
        size: 11,
        color: rgb(0.2, 0.2, 0.2),
      });
      
      // Draw a handwritten-style signature using a cursive-like path simulation
      // We'll use the italic font to simulate handwriting
      const sigFont = await pdfDoc.embedFont(StandardFonts.TimesRomanItalic);
      lastPage.drawText('John S. Doe', {
        x: 55,
        y: 50,
        font: sigFont,
        size: 22,
        color: rgb(0.0, 0.0, 0.4),
      });
      
      // Draw a line under the signature
      lastPage.drawLine({
        start: { x: 50, y: 44 },
        end: { x: 200, y: 44 },
        thickness: 0.5,
        color: rgb(0.4, 0.4, 0.4),
      });
      
      stampedPdfBytes = await pdfDoc.save();
    } catch (pdfErr) {
      // If PDF manipulation fails, just use the original buffer
      stampedPdfBytes = pdfBuffer;
    }
    
    // Hash the stamped PDF content
    const hash = crypto.createHash('sha256').update(Buffer.from(stampedPdfBytes)).digest('hex');
    const hashBigInt = BigInt('0x' + hash.slice(0, 15)) % privateKey.n;
    
    // Sign with the recovered private key (same math as the original signer used)
    const signature = toyRSASign(hashBigInt, privateKey);
    
    // Verify the signature works
    const verified = toyRSAVerify(hashBigInt, signature, publicKey);
    
    // Encode signature as base64 (same format: 8 bytes BigUInt64BE)
    const sigBytes = Buffer.alloc(8);
    sigBytes.writeBigUInt64BE(signature);
    const sigB64 = sigBytes.toString('base64');
    
    // Encode the PDF as base64 for PQC-DOCUMENT block
    const pdfB64 = Buffer.from(stampedPdfBytes).toString('base64');
    
    // Use the EXACT same certificate from the original signed document
    const certPEM = certificate || '';
    
    // Build signature trailer in the exact same format as the original
    const signatureBlock = [
      '',
      '% ---- PQC DEMO SIGNATURE (trailing bytes, ignored by PDF viewers) ----',
      certPEM,
      '-----BEGIN PQC-DOCUMENT-----',
      pdfB64,
      '-----END PQC-DOCUMENT-----',
      '-----BEGIN PQC-SIGNATURE-----',
      sigB64,
      '-----END PQC-SIGNATURE-----',
      ''
    ].join('\n');
    
    // Append signature to PDF
    const signedPdf = Buffer.concat([Buffer.from(stampedPdfBytes), Buffer.from(signatureBlock)]);
    
    const signedFilename = `signed-${req.file.filename}`;
    const signedPath = path.join(__dirname, 'uploads', signedFilename);
    fs.writeFileSync(signedPath, signedPdf);
    
    res.json({
      success: true,
      verified,
      signature: signature.toString(),
      signatureB64: sigB64,
      hash: hashBigInt.toString(),
      signedFilename,
      downloadUrl: `/api/download/${signedFilename}`,
      previewUrl: `/api/preview/${signedFilename}`,
      message: verified 
        ? '✓ Document successfully signed with cracked private key! Signature verified.' 
        : '✗ Signature verification failed.'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Preview file (inline PDF)
app.get('/api/preview/:filename', (req, res) => {
  const filepath = path.join(__dirname, 'uploads', req.params.filename);
  if (!fs.existsSync(filepath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${req.params.filename}"`);
  fs.createReadStream(filepath).pipe(res);
});

// Download file
app.get('/api/download/:filename', (req, res) => {
  const filepath = path.join(__dirname, 'uploads', req.params.filename);
  if (!fs.existsSync(filepath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.download(filepath);
});

app.listen(PORT, () => {
  console.log(`🔓 Digital Signature Attack Demo running at http://localhost:${PORT}`);
});
