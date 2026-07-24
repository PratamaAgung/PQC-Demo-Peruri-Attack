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
// Root CA — Pre-cracked at startup
// ============================================================
// The Root CA has a 64-bit RSA key that we factor using Shor's (simulated)
const ROOT_CA_PEM = fs.readFileSync(path.join(__dirname, 'certs', 'public_root_ca.pem'), 'utf8');
const ROOT_CA_CERT = forge.pki.certificateFromPem(ROOT_CA_PEM);
// Pre-computed cracked Root CA private key (N=11533841872092099193, p=3563593459, q=3236576227)
const ROOT_CA_PRIVATE = {
  n: 11533841872092099193n,
  e: 65537n,
  d: 839647215150339437n,
  p: 3563593459n,
  q: 3236576227n
};

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
// X.509 Certificate Parsing & Generation
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

/**
 * Generate a signer certificate signed by the cracked Root CA.
 * Uses node-forge to build the cert structure, then patches the signature
 * with our toy RSA since forge can't handle 64-bit keys natively.
 */
function generateSignerCertSignedByRootCA(signerPublicKey) {
  // Create signer cert using forge
  const cert = forge.pki.createCertificate();
  
  cert.publicKey = forge.pki.setRsaPublicKey(
    new forge.jsbn.BigInteger(signerPublicKey.n.toString()),
    new forge.jsbn.BigInteger(signerPublicKey.e.toString())
  );
  
  cert.serialNumber = crypto.randomBytes(16).toString('hex');
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 2);
  
  // Signer subject
  cert.setSubject([
    { name: 'countryName', value: 'ID' },
    { name: 'stateOrProvinceName', value: 'DKI Jakarta' },
    { name: 'organizationName', value: 'INA Digital' },
    { name: 'organizationalUnitName', value: 'Document Signing' },
    { name: 'commonName', value: 'INA Digital Document Signer 2026' }
  ]);
  
  // Issuer = Root CA subject
  cert.setIssuer(ROOT_CA_CERT.subject.attributes);
  
  // Extensions
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, critical: true }
  ]);
  
  // Get the TBS (to-be-signed) certificate in DER
  // We need to sign this with the Root CA's private key
  cert.siginfo.algorithmOid = forge.oids['sha256WithRSAEncryption'];
  const tbsCertDer = forge.asn1.toDer(forge.pki.getTBSCertificate(cert));
  const tbsBytes = Buffer.from(tbsCertDer.getBytes(), 'binary');
  
  // Hash TBS with SHA-256
  const tbsHash = crypto.createHash('sha256').update(tbsBytes).digest('hex');
  let hashInt = BigInt('0x' + tbsHash) % ROOT_CA_PRIVATE.n;
  if (hashInt === 0n) hashInt = 1n;
  
  // Sign with Root CA private key
  const sigInt = modPow(hashInt, ROOT_CA_PRIVATE.d, ROOT_CA_PRIVATE.n);
  
  // Encode signature as 8 bytes
  const sigBuf = Buffer.alloc(8);
  sigBuf.writeBigUInt64BE(sigInt);
  
  // Patch the cert's signature
  cert.signature = sigBuf.toString('binary');
  cert.signatureOid = forge.oids['sha256WithRSAEncryption'];
  cert.siginfo.algorithmOid = forge.oids['sha256WithRSAEncryption'];
  
  return forge.pki.certificateToPem(cert);
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
  
  const command = `LC_ALL=C sed -n '/BEGIN CERT/,/END CERT/p' ${filename}`;
  
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
  
  // --- Brute Force Trial Division (non-optimized, limited) ---
  // Run brute force for a limited number of iterations to measure speed,
  // then extrapolate how long it would take to finish
  const bruteStart = process.hrtime.bigint();
  const BRUTE_LIMIT = 1_000_000n; // limit to 1M iterations for speed
  let bruteP = null, bruteQ = null, bruteIterations = 0n;
  for (let i = 2n; i * i <= nBig; i++) {
    bruteIterations++;
    if (nBig % i === 0n) {
      bruteP = i;
      bruteQ = nBig / i;
      break;
    }
    if (bruteIterations >= BRUTE_LIMIT) break;
  }
  const bruteEnd = process.hrtime.bigint();
  const bruteTimeNs = Number(bruteEnd - bruteStart);
  const bruteTimeMs = bruteTimeNs / 1_000_000;
  
  // Calculate how long full brute force would take
  const sqrtN = Math.ceil(Math.sqrt(Number(nBig)));
  const timePerIterMs = bruteTimeMs / Number(bruteIterations);
  const estimatedFullBruteMs = timePerIterMs * sqrtN;
  const estimatedFullBruteSec = estimatedFullBruteMs / 1000;
  
  // --- Shor's Algorithm (simulated via Pollard's Rho) ---
  const shorStart = process.hrtime.bigint();
  const result = shorsAlgorithm(n);
  const shorEnd = process.hrtime.bigint();
  const shorTimeNs = Number(shorEnd - shorStart);
  const shorTimeMs = shorTimeNs / 1_000_000;
  
  if (result.success) {
    const p = result.p;
    const q = result.q;
    const phi = (p - 1n) * (q - 1n);
    const d = modInverse(eBig, phi);
    
    const speedup = estimatedFullBruteSec > 0 ? (estimatedFullBruteMs / shorTimeMs).toFixed(0) : '∞';
    
    res.json({
      success: true,
      steps: result.steps,
      factors: { p: p.toString(), q: q.toString() },
      privateKey: { n: nBig.toString(), e: eBig.toString(), d: d.toString() },
      message: 'Private key successfully derived from public key using Shor\'s algorithm!',
      comparison: {
        bruteForce: {
          sampledIterations: bruteIterations.toString(),
          sampledTimeMs: bruteTimeMs.toFixed(2),
          estimatedTotalIterations: sqrtN.toLocaleString(),
          estimatedTotalTimeSec: estimatedFullBruteSec.toFixed(1),
          found: bruteP !== null
        },
        shor: {
          timeMs: shorTimeMs.toFixed(2)
        },
        speedup,
        extrapolation: {
          rsa2048BruteForceYears: '> 10^300',
          rsa2048ShorEstimate: '~10 hours (future quantum computer, ~4000 logical qubits)',
          note: 'Trial division: O(√N). For RSA-2048, √N ≈ 2^1024 — impossible for any classical computer. Shor\'s algorithm: O((log N)³) — polynomial time on quantum hardware.'
        }
      }
    });
  } else {
    res.status(400).json({ success: false, steps: result.steps, error: 'Failed to factor N' });
  }
});

// Step 4 & 5: Sign a new document with the cracked private key
app.post('/api/sign-document', upload.single('pdf'), async (req, res) => {
  try {
    const { n, e, d, certificate, sigX, sigY, sigPage } = req.body;
    
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    const privateKey = { n: BigInt(n), e: BigInt(e), d: BigInt(d) };
    const publicKey = { n: BigInt(n), e: BigInt(e) };
    
    // Read the uploaded PDF
    const pdfBuffer = fs.readFileSync(req.file.path);
    
    // Add visual signature to the PDF
    // Attacker can control position via sigX, sigY, sigPage
    const posX = parseFloat(sigX) || 50;
    const posY = parseFloat(sigY) || 80;
    const pageNum = parseInt(sigPage) || 1; // 1-indexed
    
    let stampedPdfBytes;
    try {
      const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
      const pages = pdfDoc.getPages();
      const targetPage = pages[Math.min(pageNum - 1, pages.length - 1)] || pages[pages.length - 1];
      
      // Draw "Irwan" signature in latin/cursive style
      const sigFont = await pdfDoc.embedFont(StandardFonts.TimesRomanItalic);
      
      targetPage.drawText('Irwan', {
        x: posX,
        y: posY,
        font: sigFont,
        size: 26,
        color: rgb(0.0, 0.0, 0.3),
      });
      
      // Draw a line under the signature
      targetPage.drawLine({
        start: { x: posX - 5, y: posY - 8 },
        end: { x: posX + 100, y: posY - 8 },
        thickness: 0.5,
        color: rgb(0.3, 0.3, 0.3),
      });
      
      stampedPdfBytes = await pdfDoc.save();
    } catch (pdfErr) {
      // If PDF manipulation fails, just use the original buffer
      stampedPdfBytes = pdfBuffer;
    }
    
    // Hash the stamped PDF content (full SHA-256 as integer mod N, same as verifier)
    const hash = crypto.createHash('sha256').update(Buffer.from(stampedPdfBytes)).digest('hex');
    let hashBigInt = BigInt('0x' + hash) % privateKey.n;
    if (hashBigInt === 0n) hashBigInt = 1n; // guard against zero hash
    
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
    // BUT re-sign it with the cracked Root CA so the chain validates
    const signerCertPEM = generateSignerCertSignedByRootCA(publicKey);
    const certPEM = signerCertPEM.trim();
    
    // Build signature trailer in the exact same format as the original
    const signatureBlock = [
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
    
    // Append signature trailer directly after PDF content (no extra separator)
    // The PQC-DOCUMENT must decode to exactly the bytes before the trailer marker
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🔓 Digital Signature Attack Demo running at http://0.0.0.0:${PORT}`);
});
