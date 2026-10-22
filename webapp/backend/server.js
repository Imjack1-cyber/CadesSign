const express = require('express');
const multer = require('multer');
const { execFile } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const PORT = Number(process.env.PORT) || 3001;
// Fat JAR built by `mvn package` in the repository root
const JAR_PATH = process.env.JAR_PATH
    || path.join(__dirname, '../../target/cades-lt-demo-1.0.0-SNAPSHOT-fat.jar');

const JAVA_TIMEOUT_MS = 120_000;
const JAVA_MAX_BUFFER = 16 * 1024 * 1024;

const app = express();

// Uploads go to /webapp/backend/uploads/ and are deleted after each request
const upload = multer({
    dest: path.join(__dirname, 'uploads/'),
    limits: { fileSize: 50 * 1024 * 1024, files: 6 },
});

// Point DB to /webapp/database/metrics.db
const dbPath = process.env.DB_PATH || path.join(__dirname, '../database/metrics.db');
const db = new sqlite3.Database(dbPath);

// Point schema to /webapp/database/schema.sql
const schemaPath = path.join(__dirname, '../database/schema.sql');
const initDbSql = fs.readFileSync(schemaPath, 'utf8');
db.serialize(() => {
    db.exec(initDbSql, (err) => {
        if (err) console.error('Failed to initialise the database:', err.message);
    });
    // Databases created before the success column existed
    db.run('ALTER TABLE operations ADD COLUMN success BOOLEAN', (err) => {
        if (err && !/duplicate column/i.test(err.message)) {
            console.error('Failed to migrate the database:', err.message);
        }
    });
});

app.use(express.json());

// Helper to track metrics in SQLite
function trackOperation(row) {
    db.run(`
        INSERT INTO operations (action, signature_level, packaging, digest, used_tsa, used_ocsp, used_crl, used_keystore, success)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        row.action,
        row.signatureLevel || null,
        row.packaging || null,
        row.digest || null,
        row.usedTsa ? 1 : 0,
        row.usedOcsp ? 1 : 0,
        row.usedCrl ? 1 : 0,
        row.usedKeystore ? 1 : 0,
        row.success ? 1 : 0,
    ], (err) => {
        if (err) console.error('Failed to track operation:', err.message);
    });
}

/** Maps the CLI's "Level reached : CAdES-BASELINE-LT" to the wizard's short form (B, T, LT, LTA). */
function levelReached(stdout) {
    const match = /Level reached\s*:\s*CAdES-BASELINE-(\S+)/.exec(stdout || '');
    return match ? match[1] : null;
}

function removeUploads(req, ...extra) {
    const paths = Object.values(req.files || {}).flat().map(f => f.path).concat(extra);
    for (const p of paths) {
        fs.rm(p, { force: true }, () => {});
    }
}

function runCli(args, callback) {
    execFile('java', ['-jar', JAR_PATH, ...args],
        { timeout: JAVA_TIMEOUT_MS, maxBuffer: JAVA_MAX_BUFFER }, callback);
}

// Define all possible file fields the frontend might send
const allowedFileFields = [
    { name: 'inputDocument', maxCount: 1 },
    { name: 'signedDocument', maxCount: 1 },
    { name: 'originalFile', maxCount: 1 },
    { name: 'keystoreFile', maxCount: 1 },
    { name: 'signerFile', maxCount: 1 },
    { name: 'tsaFile', maxCount: 1 }
];

app.post('/api/sign', upload.fields(allowedFileFields), (req, res) => {
    const options = req.body;
    const files = req.files;

    if (!files || !files.inputDocument) {
        removeUploads(req);
        return res.status(400).json({ error: "inputDocument is required" });
    }

    // Signing needs keys: an uploaded keystore, an uploaded signer file,
    // or an explicit request to generate a fresh keystore.
    const generateKeystore = options.generateKeystore === 'true';
    if (!files.keystoreFile && !files.signerFile && !generateKeystore) {
        removeUploads(req);
        return res.status(400).json({
            error: 'A keystore is required: upload a keystore, upload signer and TSA files, or generate a new keystore',
        });
    }

    const inputPath = files.inputDocument[0].path;
    const outputPath = `${inputPath}.p7s`;
    const generatedPath = generateKeystore ? `${inputPath}.generated.p12` : null;
    const temporaryPaths = [outputPath, generatedPath].filter(Boolean);

    // Secure argument building (prevents command injection)
    const args = ['sign', inputPath, '-o', outputPath];

    if (options.signatureLevel) args.push('--level', options.signatureLevel);
    if (options.packaging) args.push('--packaging', options.packaging);
    if (options.digest) args.push('--digest', options.digest);
    if (options.tsaUrl) args.push('--tsa-url', options.tsaUrl);
    if (options.ocspUrl) args.push('--ocsp-url', options.ocspUrl);
    if (options.crlUrl) args.push('--crl-url', options.crlUrl);
    if (generateKeystore) {
        args.push('--generate-keystore', generatedPath);
    } else if (files.keystoreFile) {
        args.push('--keystore', files.keystoreFile[0].path);
    } else {
        args.push('--signer', files.signerFile[0].path);
        if (options.signerPassword) args.push('--signer-password', options.signerPassword);
    }
    if (options.keystorePassword) args.push('--keystore-password', options.keystorePassword);
    if (files.tsaFile) {
        args.push('--tsa', files.tsaFile[0].path);
        if (options.tsaPassword) args.push('--tsa-password', options.tsaPassword);
    }

    runCli(args, (error, stdout, stderr) => {
        trackOperation({
            action: 'SIGN',
            signatureLevel: options.signatureLevel,
            packaging: options.packaging,
            digest: options.digest,
            usedTsa: !!options.tsaUrl,
            usedOcsp: !!options.ocspUrl,
            usedCrl: !!options.crlUrl,
            usedKeystore: !!(files.keystoreFile || files.signerFile),
            success: !error,
        });

        if (error) {
            removeUploads(req, ...temporaryPaths);
            const message = error.killed ? 'Signing timed out' : (stderr || stdout || error.message);
            return res.status(500).json({ error: message });
        }
        // The CLI's self-check (level reached, passed?) for the result page
        // without the "Signature written to <server path>" line.
        const summary = stdout
            .replace(/^Signature written to .*\n?/m, '')
            .replace(/^Generated new keystore at .*\n?/m, '')
            .trim();
        res.set('X-Cades-Summary', encodeURIComponent(summary));
        // A generated keystore is small (a few KB), so it travels base64-encoded
        // in a header next to the signature rather than in a second request.
        if (generatedPath) {
            res.set('X-Cades-Keystore', fs.readFileSync(generatedPath).toString('base64'));
        }
        res.download(outputPath, `${files.inputDocument[0].originalname}.p7s`,
            () => removeUploads(req, ...temporaryPaths));
    });
});

app.post('/api/verify', upload.fields(allowedFileFields), (req, res) => {
    const options = req.body;
    const files = req.files;

    if (!files || !files.signedDocument) {
        removeUploads(req);
        return res.status(400).json({ error: "signedDocument is required" });
    }

    const signedPath = files.signedDocument[0].path;
    const args = ['verify'];

    if (files.originalFile) {
        args.push(files.originalFile[0].path); // original goes first if detached
    }
    args.push(signedPath, '--report', options.reportFormat || 'simple');

    if (files.keystoreFile) {
        args.push('--keystore', files.keystoreFile[0].path);
        if (options.keystorePassword) args.push('--keystore-password', options.keystorePassword);
    }
    if (options.noKeystoreTrust === 'true') {
        args.push('--no-keystore-trust');
    }

    runCli(args, (error, stdout, stderr) => {
        removeUploads(req);

        // Re-fetches of the full report repeat a verification already counted
        if (options.track !== 'false') {
            trackOperation({
                action: 'VERIFY',
                signatureLevel: levelReached(stdout),
                packaging: files.originalFile ? 'DETACHED' : 'ENVELOPING',
                usedKeystore: !!files.keystoreFile,
                success: !error && /TOTAL_PASSED/.test(stdout),
            });
        }

        // CAdES Verifier outputs the actual result to stdout even on failure to reach LT.
        const errorOutput = error && error.killed ? 'Verification timed out' : stderr;
        res.json({ output: stdout, errorOutput, success: !error });
    });
});

app.get('/api/stats', (req, res) => {
    db.all(`SELECT * FROM operations ORDER BY timestamp DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Upload errors (file too large, unexpected field) become 400s instead of HTML 500s
app.use((err, req, res, next) => {
    removeUploads(req);
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: err.message });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`Secure CAdES API running on port ${PORT}`));
