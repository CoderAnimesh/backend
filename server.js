// server.js (ESM)
import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import { Resend } from "resend";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import QRCode from "qrcode";
import multer from "multer";
import path from "path";
import PDFDocument from "pdfkit";
import { fileURLToPath } from "url";
import { customAlphabet } from "nanoid";
import { google } from "googleapis";
import stream from "stream";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_prod";

// ---------- WebAuthn Configuration ----------
// CHANGE THIS TO MATCH YOUR FRONTEND URL EXACTLY
// If using VS Code Live Server, it is usually 127.0.0.1
// ---------- WebAuthn Configuration ----------
// FIX: rpID must match the IP in your browser address bar
// ---------- WebAuthn Configuration ----------
// MUST be 'localhost'. IP addresses (127.0.0.1) are blocked by WebAuthn spec.
const rpID = 'localhost'; 
const origin = 'http://localhost:5500';

// In-Memory Storage for Fingerprints (Note: Resets when server restarts)
const localAuthDB = {}; 

const getLocalUser = (username) => {
    if (!localAuthDB[username]) {
        localAuthDB[username] = { 
            id: username, 
            username: username, 
            authenticators: [], 
            currentChallenge: "" 
        };
    }
    return localAuthDB[username];
};

// ---------- Postgres (Neon) ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- Express Setup ----------
const app = express();
app.use(helmet());
app.use(express.json());

// CORS: Allow both localhost and 127.0.0.1
app.use(cors({ 
    origin: [
        "http://localhost:5500", 
        "http://127.0.0.1:5500", 
        "http://localhost:5173",
        "https://quantumquirksuoa.netlify.app",
        "https://quantumquirksuoa.co.in"
    ], 
    credentials: true 
}));

app.use("/gallery", (req, res, next) => { 
    res.setHeader("Access-Control-Allow-Origin", "https://quantumquirksuoa.co.in"); 
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin"); 
    next(); 
}, express.static(path.join(__dirname, "public/gallery")));

// ---------- Resend & OTP Setup ----------
const resend = new Resend(process.env.RESEND_API_KEY);
const EMAIL_FROM = process.env.EMAIL_FROM || "Quantum Quirks <onboarding@resend.dev>";
const otpStore = new Map();
const OTP_EXP_MINUTES = Number(process.env.OTP_EXP_MINUTES || 10);

function createOTP(len = 6) { return Array.from({ length: len }, () => Math.floor(Math.random() * 10)).join(""); }
function setOTP(email, code) { otpStore.set(email.toLowerCase(), { code, expiresAt: Date.now() + OTP_EXP_MINUTES * 60 * 1000, verified: false }); }
function getOTP(email) { return otpStore.get((email || "").toLowerCase()); }
function clearOTP(email) { otpStore.delete((email || "").toLowerCase()); }

// ---------- Google Drive Setup ----------
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);
oauth2Client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
const drive = google.drive({ version: "v3", auth: oauth2Client });

async function getOrCreateSubfolder(folderName, parentId) {
  try {
    const query = `mimeType='application/vnd.google-apps.folder' and name='${folderName.replace(/'/g, "\\'")}' and '${parentId}' in parents and trashed=false`;
    const res = await drive.files.list({ q: query, fields: 'files(id, name)', spaces: 'drive' });
    if (res.data.files.length > 0) return res.data.files[0].id;
    const folder = await drive.files.create({ resource: { name: folderName, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] }, fields: 'id' });
    await drive.permissions.create({ fileId: folder.data.id, requestBody: { role: "reader", type: "anyone" } });
    return folder.data.id;
  } catch (err) { throw new Error("Failed to manage event folder"); }
}

async function uploadToGoogleDrive(fileBuffer, fileName, mimeType, folderName) {
  try {
    let targetFolderId = process.env.GOOGLE_DRIVE_FOLDER_ID;
    
    // Check/Create Subfolder
    if (folderName) targetFolderId = await getOrCreateSubfolder(folderName, targetFolderId);

    // Create Stream
    const bufferStream = new stream.PassThrough();
    bufferStream.end(fileBuffer);

    // Upload
    const createResponse = await drive.files.create({
      media: { mimeType: mimeType, body: bufferStream },
      requestBody: { name: fileName, parents: [targetFolderId] },
      fields: "id"
    });

    const fileId = createResponse.data.id;

    // Set Permissions (Essential for the link to work)
    await drive.permissions.create({
      fileId: fileId,
      requestBody: { role: "reader", type: "anyone" }
    });

    // --- THE FIX ---
    // Instead of getting the thumbnailLink (which expires), we construct the permanent link.
    const permanentUrl = `https://lh3.googleusercontent.com/d/${fileId}`;

    return { publicUrl: permanentUrl, fileId };

  } catch (error) {
    console.error("Google Drive API Error:", error);
    throw new Error("Failed to upload to Google Drive");
  }
}

// ---------- Helpers ----------
const nanoid = customAlphabet("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", 5);

async function generateUniqueCode(client, eventId) {
  for (let i = 0; i < 20; i++) {
    const code = "TECH" + nanoid();
    const res = await client.query("SELECT id FROM participants WHERE event_id=$1 AND code=$2", [eventId, code]);
    if (res.rows.length === 0) return code;
  }
  throw new Error("Unable to generate unique participant code");
}

function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: "8h" }); }

function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization;
  if (!hdr) return res.status(401).json({ ok: false, message: "Authorization required" });
  try { const token = hdr.split(" ")[1]; req.user = jwt.verify(token, JWT_SECRET); next(); } catch (err) { return res.status(401).json({ ok: false, message: "Invalid token" }); }
}

function requireRole(role) { return (req, res, next) => { if (!req.user || req.user.role !== role) return res.status(403).json({ ok: false, message: "Forbidden" }); next(); }; }

// ---------- DB Initialization ----------
(async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS organizers (
        id SERIAL PRIMARY KEY ,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        phone VARCHAR(20) NOT NULL,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(200) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'organizer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS contact_messages (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS volunteers (
        id SERIAL PRIMARY KEY,
        vol_id VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(200) NOT NULL,
        name VARCHAR(100),
        email VARCHAR(100),
        phone VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(100) UNIQUE,
        name VARCHAR(200) NOT NULL,
        entry_amount INT NOT NULL, 
        description TEXT,
        start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_date TIMESTAMP NOT NULL
      );
      CREATE TABLE if not exists gallery_images (
        id SERIAL PRIMARY KEY,
        event_id INT REFERENCES events(id),
        image_path TEXT NOT NULL,
        description TEXT,
        event_date DATE,
        drive_file_id VARCHAR(255)
      );
      CREATE TABLE IF NOT EXISTS participants (
        id SERIAL PRIMARY KEY,
        event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
        name VARCHAR(200) NOT NULL,
        batch VARCHAR(50) NOT NULL,
        semester VARCHAR(50) NOT NULL,
        father_name VARCHAR(200),
        mother_name VARCHAR(200),
        gender VARCHAR(20),
        email VARCHAR(200) NOT NULL,
        phone VARCHAR(20),
        preferred_language VARCHAR(50) NOT NULL,
        payment VARCHAR(20) DEFAULT 'unpaid',
        transaction_id VARCHAR(100),
        code VARCHAR(16) UNIQUE, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uniq_email_event UNIQUE (event_id, email)
      );
      CREATE TABLE IF NOT EXISTS allocations (
        id SERIAL PRIMARY KEY,
        event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
        participant_id INTEGER REFERENCES participants(id) ON DELETE CASCADE,
        pc_number INTEGER NOT NULL,
        allocated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT uniq_pc_per_event UNIQUE (event_id, pc_number),
        CONSTRAINT uniq_participant_alloc UNIQUE (participant_id)
      );
      ALTER TABLE organizers ADD COLUMN IF NOT EXISTS last_password_reset TIMESTAMP DEFAULT (CURRENT_TIMESTAMP - INTERVAL '16 days');
    
    ALTER TABLE events ADD COLUMN IF NOT EXISTS allowed_languages TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS participation_type VARCHAR(20) DEFAULT 'Solo';
ALTER TABLE events ADD COLUMN IF NOT EXISTS max_group_size INT DEFAULT 1;
      `);

    await pool.query(`
      DO $$ BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='participants' AND column_name='transaction_id') THEN 
          ALTER TABLE participants ADD COLUMN transaction_id VARCHAR(100); 
        END IF; 
      END $$;
    `);

    console.log("✅ DB tables ensured");
  } catch (err) {
    console.error("DB init error:", err);
    process.exit(1);
  }
})();

// ---------- 🎨 EMAIL TEMPLATES ----------
// ---------- 🎨 ENHANCED EMAIL TEMPLATES ----------

// ---------- 🖨️ PDF GENERATOR HELPER ----------
function generateTicketPDF(eventName, participantName, code, qrBuffer) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A5', margin: 40 });
      const buffers = [];
      
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => resolve(Buffer.concat(buffers)));

      // Dark Header Background
      doc.rect(0, 0, doc.page.width, 100).fill('#0d1117');
      
      // Title
      doc.fillColor('#FFFFFF').fontSize(20).text("QUANTUM QUIRKS", 0, 40, { align: 'center' });
      
      // Ticket Details
      doc.moveDown(4);
      doc.fillColor('#000000');
      
      doc.fontSize(10).text("EVENT", { align: 'center' });
      doc.fontSize(16).font('Helvetica-Bold').text(eventName, { align: 'center' });
      doc.moveDown(1);
      
      doc.fontSize(10).font('Helvetica').text("PARTICIPANT", { align: 'center' });
      doc.fontSize(14).font('Helvetica-Bold').text(participantName, { align: 'center' });
      doc.moveDown(1);

      doc.fontSize(10).font('Helvetica').text("TICKET CODE", { align: 'center' });
      doc.fontSize(18).fillColor('#6366f1').font('Courier-Bold').text(code, { align: 'center' });
      
      doc.moveDown(1);
      
      // Draw QR Code Image (Centered)
      const qrWidth = 150;
      const x = (doc.page.width - qrWidth) / 2;
      doc.image(qrBuffer, x, doc.y, { width: qrWidth });
      
      // Footer
      doc.text("Present this QR code at the entrance.", x, doc.y + qrWidth + 10, { width: qrWidth, align: 'center', size: 8 });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

// ---------- 🎨 UPDATED HTML TEMPLATE (Accepts CID) ----------
const getTicketHtml = (eventName, participantName, code, cid) => {
  return `
  <!DOCTYPE html>
  <html>
  <body style="margin:0; padding:0; background-color:#0d1117; font-family: 'Courier New', monospace;">
    <table role="presentation" width="100%" style="background-color:#0d1117;">
      <tr>
        <td align="center" style="padding: 40px 10px;">
          <table role="presentation" width="100%" style="max-width: 500px; background-color: #161b22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden;">
            <tr>
              <td style="padding: 30px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0 0 10px 0;">ACCESS GRANTED</h1>
                <h2 style="color: #58a6ff;">${eventName}</h2>
                <div style="background-color: #ffffff; padding: 20px; border-radius: 8px; display: inline-block; margin: 20px auto;">
                  <img src="cid:${cid}" alt="Ticket QR" width="200" height="200" style="display: block;" />
                </div>
                <p style="color: #c9d1d9; font-size: 16px; font-weight: bold; letter-spacing: 2px;">${code}</p>
                <p style="color: #8b949e; font-size: 12px;">Participant: ${participantName}</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
  </html>`;
};

// 2. PC ALLOCATION EMAIL (Matrix Green Theme)
const getPcAllocationHtml = (eventName, participantName, pcNumber) => {
  return `
  <!DOCTYPE html>
  <html>
  <body style="margin:0; padding:0; background-color:#000000; font-family: 'Courier New', monospace;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#000000;">
      <tr>
        <td align="center" style="padding: 40px 10px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 500px; border: 2px solid #00ff00; background-color: #0a0a0a; box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);">
            <tr>
              <td style="padding: 30px; text-align: center;">
                <h2 style="color: #00ff00; margin: 0 0 20px 0; letter-spacing: 2px; font-size: 18px; border-bottom: 1px solid #00ff00; padding-bottom: 15px;">
                  >> SYSTEM_OVERRIDE
                </h2>
                
                <p style="color: #ffffff; margin-bottom: 5px;">USER DETECTED: <strong>${participantName}</strong></p>
                <p style="color: #008f00; font-size: 12px; margin-bottom: 30px;">TARGET: ${eventName}</p>

                <div style="background-color: #001100; border: 1px dashed #00ff00; padding: 30px; margin-bottom: 30px;">
                  <p style="color: #008f00; font-size: 10px; margin: 0; letter-spacing: 2px;">TERMINAL ASSIGNMENT</p>
                  <h1 style="color: #ffffff; font-size: 64px; margin: 10px 0; text-shadow: 0 0 10px #00ff00;">${pcNumber}</h1>
                </div>

                <p style="color: #00ff00; font-size: 14px;">> PROCEED TO STATION IMMEDIATELY.</p>
              </td>
            </tr>
            <tr>
              <td style="background-color: #001100; padding: 10px; text-align: right; border-top: 1px solid #00ff00;">
                <p style="color: #008f00; font-size: 10px; margin: 0;">TERMINAL_ALLOCATION_PROTOCOL // v2.0</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
  </html>`;
};


// 2. CHECK EMAIL
app.post("/api/check-email", async (req, res) => {
  const { email, eventId } = req.body;
  try {
    const r = await pool.query("SELECT id FROM participants WHERE email=$1 AND event_id=$2", [email, eventId]);
    if (r.rows.length > 0) return res.json({ ok: false, message: "Email already registered" });
    return res.json({ ok: true });
  } catch (err) { return res.status(500).json({ ok: false }); }
});

// 3. OTP ROUTES
app.post("/api/otp/:eventId/send", async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ ok: false, message: "Email required" });
  const code = createOTP(6);
  setOTP(email, code);
  try {
    await resend.emails.send({ from: EMAIL_FROM, to: email, subject: "Your Quantum Quirks OTP", html: `<p>Hello ${name || ""},</p><p>Your OTP code is:</p><h2>${code}</h2>` });
    return res.json({ ok: true, message: "OTP sent" });
  } catch (err) { return res.status(500).json({ ok: false }); }
});

app.post("/api/otp/:eventId/verify", (req, res) => {
  const { email, otp } = req.body;
  const record = getOTP(email);
  if (!record) return res.status(400).json({ ok: false, message: "OTP not found" });
  if (Date.now() > record.expiresAt) { clearOTP(email); return res.status(400).json({ ok: false, message: "Expired" }); }
  if (record.code !== otp) return res.status(400).json({ ok: false, message: "Invalid OTP" });
  record.verified = true;
  otpStore.set(email.toLowerCase(), record);
  return res.json({ ok: true });
});

// 4. PARTICIPANT ENROLLMENT
app.post("/api/participants/pre-enroll", async (req, res) => {
  try {
    let { email, eventId } = req.body;
    eventId = Number(eventId);
    if (!eventId || isNaN(eventId)) return res.status(400).json({ ok: false, message: "Invalid Event ID detected." });

    const otpRec = getOTP(email);
    if (!otpRec || !otpRec.verified) return res.status(400).json({ ok: false, message: "Email not verified" });

    const dup = await pool.query("SELECT id FROM participants WHERE event_id=$1 AND email=$2", [eventId, email]);
    if (dup.rows.length > 0) return res.status(400).json({ ok: false, message: "Email already registered for this event" });

    const ev = await pool.query("SELECT id, name, entry_amount FROM events WHERE id=$1", [eventId]);
    if (ev.rows.length === 0) return res.status(404).json({ ok: false, message: "Event not found" });
    
    // REPLACE THIS with your actual UPI ID
    const MY_UPI_ID = process.env.UPI_ID; 

    if (ev.rows[0].entry_amount > 0) {
      return res.json({ ok: true, requiresPayment: true, amount: ev.rows[0].entry_amount, eventName: ev.rows[0].name, upiId: MY_UPI_ID, message: "Scan QR to pay." });
    } else {
      return res.json({ ok: true, requiresPayment: false, message: "Free event." });
    }
  } catch (err) { console.error("Pre-enroll error:", err); res.status(500).json({ ok: false, message: "Server validation failed" }); }
});

// ... existing imports ...

// 4. CONFIRM ENROLL (UPDATED FOR QR & PDF)
app.post("/api/participants/confirm-enroll", async (req, res) => {
  try {
    let { name, email, eventId, transactionId, ...otherFields } = req.body;
    eventId = Number(eventId);
    const otpRec = getOTP(email);
    if (!otpRec?.verified) return res.status(400).json({ ok: false, message: "Session expired." });

    const ev = await pool.query("SELECT id, name, entry_amount, slug FROM events WHERE id=$1", [eventId]);
    const event = ev.rows[0];
    let status = event.entry_amount > 0 ? 'pending_verification' : 'paid';

    const client = await pool.connect();
    let finalCode = null;
    try {
      await client.query("BEGIN");
      finalCode = await generateUniqueCode(client, eventId);
      await client.query(
        `INSERT INTO participants (event_id, name, email, payment, transaction_id, code, batch, semester, father_name, mother_name, gender, phone, preferred_language) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [eventId, name, email, status, transactionId || null, finalCode, otherFields.batch, otherFields.semester, otherFields.fatherName, otherFields.motherName, otherFields.gender, otherFields.phone, otherFields.preferredLanguage]
      );
      await client.query("COMMIT");
    } catch (err) { await client.query("ROLLBACK"); throw err; } finally { client.release(); }

    if (status === 'paid') {
      // 1. Generate QR Buffer (Raw Image)
      const qrBuffer = await QRCode.toBuffer(finalCode, { color: { dark: '#000000', light: '#ffffff' }, width: 300, margin: 1 });
      
      // 2. Generate PDF Buffer (Pass QR Buffer to it)
      const pdfBuffer = await generateTicketPDF(event.name, name, finalCode, qrBuffer);
      
      // 3. Define a Content-ID
      const qrCid = "ticket_qr_image_unique";

      // 4. Send Email with Inline Image + PDF Attachment
      await resend.emails.send({
        from: EMAIL_FROM, 
        to: email, 
        subject: `[ACCESS GRANTED] Ticket for ${event.name}`,
        html: getTicketHtml(event.name, name, finalCode, qrCid), // Reference CID here
        attachments: [
            {
                filename: 'ticket-qr.png',
                content: qrBuffer,
                cid: qrCid // This ensures it shows in the email body
            },
            {
                filename: `${event.slug || 'ticket'}.pdf`,
                content: pdfBuffer // This is the downloadable PDF
            }
        ]
      });
    } else {
      await resend.emails.send({ from: EMAIL_FROM, to: email, subject: "Payment Pending", html: "<p>Verification in progress...</p>" });
    }

    clearOTP(email);
    return res.json({ ok: true, message: "Success!", status });
  } catch (err) { console.error("Confirm error:", err); res.status(500).json({ ok: false, message: err.message }); }
});

// 5. APPROVE PAYMENT (UPDATED FOR QR & PDF)
app.post("/api/organizer/approve-payment", authMiddleware, requireRole("organizer"), async (req, res) => {
  try {
    const result = await pool.query("UPDATE participants SET payment='paid' WHERE id=$1 RETURNING *", [req.body.participantId]);
    if (result.rows.length === 0) return res.status(404).json({ ok: false });
    const user = result.rows[0];
    const evRes = await pool.query("SELECT name, slug FROM events WHERE id=$1", [user.event_id]);
    const event = evRes.rows[0];

    // Generate Buffers
    const qrBuffer = await QRCode.toBuffer(user.code, { color: { dark: '#000000', light: '#ffffff' }, width: 300, margin: 1 });
    const pdfBuffer = await generateTicketPDF(event.name, user.name, user.code, qrBuffer);
    const qrCid = "ticket_qr_image_unique";

    await resend.emails.send({
      from: EMAIL_FROM, 
      to: user.email, 
      subject: `[CONFIRMED] Ticket for ${event.name}`,
      html: getTicketHtml(event.name, user.name, user.code, qrCid),
      attachments: [
        { filename: 'ticket-qr.png', content: qrBuffer, cid: qrCid },
        { filename: `${event.slug}.pdf`, content: pdfBuffer }
      ]
    });

    res.json({ ok: true, message: "Approved & Ticket Sent" });
  } catch (err) { res.status(500).json({ ok: false }); }
});
// 5. STANDARD LOGINS
app.post("/api/organizer/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query("SELECT id, password FROM organizers WHERE username=$1", [username]);
    if (r.rows.length === 0) return res.status(401).json({ ok: false });
    if (await bcrypt.compare(password, r.rows[0].password)) {
      return res.json({ ok: true, token: signToken({ id: r.rows[0].id, username, role: "organizer" }) });
    }
    res.status(401).json({ ok: false });
  } catch (err) { res.status(500).json({ ok: false }); }
});

app.post("/api/volunteer/login", async (req, res) => {
  const { volId, password } = req.body;
  try {
    const r = await pool.query("SELECT id, password_hash FROM volunteers WHERE vol_id=$1", [volId]);
    if (r.rows.length === 0) return res.status(401).json({ ok: false });
    if (await bcrypt.compare(password, r.rows[0].password_hash)) {
      return res.json({ ok: true, token: signToken({ id: r.rows[0].id, volId, role: "volunteer" }) });
    }
    res.status(401).json({ ok: false });
  } catch (err) { res.status(500).json({ ok: false }); }
});

// 6. EVENTS MANAGEMENT
app.post("/api/events", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { name, amount, description, endDate, languages, type, groupSize } = req.body;
  try {
    const slug = name.toLowerCase().replace(/\s+/g, "-").slice(0, 80);
    
    // Ensure languages is stored as a comma-separated string
    const langString = Array.isArray(languages) ? languages.join(',') : (languages || "");

    const r = await pool.query(
      `INSERT INTO events (slug, name, entry_amount, description, end_date, allowed_languages, participation_type, max_group_size) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`, 
      [slug, name, amount, description || "", endDate, langString, type || "Solo", groupSize || 1]
    );
    res.json({ ok: true, event: r.rows[0] });
  } catch (err) { 
    console.error("Create Event Error:", err);
    res.status(500).json({ ok: false, message: "Failed to create event" }); 
  }
});

app.get("/api/events", async (req, res) => {
  try { 
    const r = await pool.query("SELECT * FROM events ORDER BY start_date DESC"); 
    res.json({ ok: true, events: r.rows }); 
  } catch (err) { 
    res.status(500).json({ ok: false }); 
  }
});

app.delete("/api/events/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  try {
    const eventId = Number(req.params.id);
    await pool.query("DELETE FROM participants WHERE event_id = $1", [eventId]);
    await pool.query("DELETE FROM events WHERE id = $1", [eventId]);
    res.json({ ok: true, message: "Event Deleted" });
  } catch (err) { 
    res.status(500).json({ ok: false, message: "Failed to delete event" }); 
  }
});

// 7. PARTICIPANT MANAGEMENT
app.post("/api/organizer/participant", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { eventId, name, fatherName, motherName, gender, email, phone, preferredLanguage } = req.body;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const code = await generateUniqueCode(client, eventId);
    const insert = await client.query(`INSERT INTO participants (event_id, name, father_name, mother_name, gender, email, phone, preferred_language, code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`, [eventId, name, fatherName, motherName, gender, email, phone, preferredLanguage, code]);
    await client.query("COMMIT");
    res.json({ ok: true, participant: insert.rows[0] });
  } catch (err) { await client.query("ROLLBACK"); res.status(500).json({ ok: false }); } finally { client.release(); }
});

app.get("/api/events/:id/participants", authMiddleware, async (req, res) => {
  try { const r = await pool.query("SELECT * FROM participants WHERE event_id=$1 ORDER BY id DESC", [req.params.id]); res.json({ ok: true, participants: r.rows }); } catch (err) { res.status(500).json({ ok: false }); }
});

app.delete("/api/participants/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  try { await pool.query("DELETE FROM participants WHERE id = $1", [req.params.id]); res.json({ ok: true, message: "Participant Deleted" }); } catch (err) { res.status(500).json({ ok: false, message: "Failed to delete participant" }); }
});

// 8. STAFF MANAGEMENT
app.post("/api/organizer/volunteer", authMiddleware, requireRole("organizer"), async (req, res) => {
  try {
    const { name, email, phone, username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(`INSERT INTO volunteers (vol_id, password_hash, name, email, phone) VALUES ($1,$2,$3,$4,$5) RETURNING *`, [username, hashed, name, email, phone]);
    res.json({ ok: true, volunteer: result.rows[0] });
  } catch (err) { res.status(500).json({ ok: false, message: "Failed to add volunteer" }); }
});

// 8. STAFF MANAGEMENT (Updated to send credentials via email)
app.post("/api/admin/organizer", authMiddleware, requireRole("organizer"), async (req, res) => {
    try {
      const { name, email, phone, username, password } = req.body;
      
      // Hash the password for the database
      const hashed = await bcrypt.hash(password, 10);
      
      // Store the organizer details
      const result = await pool.query(
        `INSERT INTO organizers (name, email, phone, username, password, role) VALUES ($1,$2,$3,$4,$5,'organizer') RETURNING *`, 
        [name, email, phone, username, hashed]
      );
  
      // --- NEW: Send Email with Credentials ---
      await resend.emails.send({
        from: EMAIL_FROM,
        to: email,
        subject: "Welcome! Your Organizer Credentials",
        html: `
          <div style="font-family: Arial, sans-serif; background-color: #0d1117; color: #c9d1d9; padding: 30px; border-radius: 8px; max-width: 500px; margin: auto; border: 1px solid #30363d;">
            <h2 style="color: #58a6ff; margin-top: 0;">Welcome to the Team, ${name}!</h2>
            <p style="font-size: 16px;">You have been successfully added as an Organizer.</p>
            <div style="background-color: #161b22; padding: 20px; border-radius: 6px; border: 1px solid #21262d; margin: 20px 0;">
              <p style="margin: 0 0 10px 0;"><strong>User ID / Username:</strong> <span style="color: #ffffff;">${username}</span></p>
              <p style="margin: 0;"><strong>Password:</strong> <span style="color: #ffffff;">${password}</span></p>
            </div>
            <p style="font-size: 14px; color: #8b949e;">Please log in using these credentials. We recommend changing your password shortly after your first login.</p>
          </div>
        `
      });
  
      res.json({ ok: true, organizer: result.rows[0], message: "Organizer added and credentials emailed." });
    } catch (err) { 
      console.error("Failed to add organizer:", err);
      res.status(500).json({ ok: false, message: "Failed to add organizer" }); 
    }
  });

// 9. ALLOCATION
async function allocatePcForParticipant(client, participantId, eventId) {
  const existing = await client.query("SELECT pc_number FROM allocations WHERE participant_id=$1", [participantId]);
  if (existing.rows.length > 0) return existing.rows[0].pc_number;
  const langRes = await client.query("SELECT preferred_language FROM participants WHERE id=$1", [participantId]);
  const myLang = langRes.rows[0].preferred_language;
  const usedRes = await client.query(`SELECT a.pc_number, p.preferred_language FROM allocations a JOIN participants p ON a.participant_id = p.id WHERE a.event_id=$1 ORDER BY a.pc_number ASC`, [eventId]);
  const used = usedRes.rows;
  let pc = 1;
  while(true){
    if(used.find(u => u.pc_number === pc)) { pc++; continue; }
    const left = used.find(u => u.pc_number === pc-1);
    const right = used.find(u => u.pc_number === pc+1);
    if((left && left.preferred_language === myLang) || (right && right.preferred_language === myLang)) { pc++; continue; }
    break;
  }
  await client.query("INSERT INTO allocations (event_id, participant_id, pc_number) VALUES ($1,$2,$3)", [eventId, participantId, pc]);
  return pc;
}

app.post("/api/organizer/allocate", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { participantId } = req.body;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Fetch name & email for email
    const p = await client.query("SELECT id, event_id, name, email FROM participants WHERE id=$1 FOR UPDATE", [participantId]);
    if (p.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false }); }
    
    const user = p.rows[0];
    const pc = await allocatePcForParticipant(client, user.id, user.event_id);
    
    // Get Event Name
    const ev = await client.query("SELECT name FROM events WHERE id=$1", [user.event_id]);
    const eventName = ev.rows[0].name;

    await client.query("COMMIT");

    // Send "Matrix" Email
    await resend.emails.send({
      from: EMAIL_FROM, to: user.email, subject: `[TERMINAL ASSIGNED] ${eventName}`,
      html: getPcAllocationHtml(eventName, user.name, `PC-${pc}`)
    });

    res.json({ ok: true, pc });
  } catch (e) { await client.query("ROLLBACK"); console.error(e); res.status(500).json({ ok: false }); } finally { client.release(); }
});

app.post("/api/verify-code", authMiddleware, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ ok: false, message: "Code required" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Fetch user details
    const p = await client.query("SELECT id, event_id, name, email FROM participants WHERE code=$1 FOR UPDATE", [code]);
    if (p.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, message: "Code not found" }); }
    
    const user = p.rows[0];
    const pc = await allocatePcForParticipant(client, user.id, user.event_id);
    
    // Get Event Name
    const ev = await client.query("SELECT name FROM events WHERE id=$1", [user.event_id]);
    const eventName = ev.rows[0].name;

    await client.query("COMMIT");

    // Send "Matrix" Email
    await resend.emails.send({
      from: EMAIL_FROM, to: user.email, subject: `[TERMINAL ASSIGNED] ${eventName}`,
      html: getPcAllocationHtml(eventName, user.name, `PC-${pc}`)
    });

    return res.json({ ok: true, message: "Success", pc });
  } catch (err) { await client.query("ROLLBACK"); console.error(err); return res.status(500).json({ ok: false }); } finally { client.release(); }
});

// 10. GALLERY
const storage = multer.memoryStorage();
const upload = multer({ storage });

app.post("/api/organizer/gallery/:eventId", authMiddleware, requireRole("organizer"), upload.single("image"), async (req, res) => {
  try {
    const eventId = Number(req.params.eventId);
    if (!req.file) return res.status(400).json({ ok: false, message: "No image" });
    const evRes = await pool.query("SELECT name, end_date FROM events WHERE id=$1", [eventId]);
    const { publicUrl, fileId } = await uploadToGoogleDrive(req.file.buffer, `${Date.now()}-${req.file.originalname}`, req.file.mimetype, evRes.rows[0].name);
    const result = await pool.query(`INSERT INTO gallery_images (event_id, image_path, description, event_date, drive_file_id) VALUES ($1,$2,$3,$4,$5) RETURNING *`, [eventId, publicUrl, req.body.description || "", evRes.rows[0].end_date, fileId]);
    res.json({ ok: true, image: result.rows[0] });
  } catch (err) { res.status(500).json({ ok: false }); }
});

app.get("/api/gallery/:eventId", async (req, res) => {
  try { const result = await pool.query("SELECT * FROM gallery_images WHERE event_id = $1 ORDER BY id ASC", [req.params.eventId]); res.json({ ok: true, images: result.rows }); } catch (err) { res.status(500).json({ ok: false }); }
});

app.delete("/api/organizer/gallery/:imageId", authMiddleware, requireRole("organizer"), async (req, res) => {
  try {
    const imgRes = await pool.query("SELECT drive_file_id FROM gallery_images WHERE id=$1", [req.params.imageId]);
    if (imgRes.rows.length === 0) return res.status(404).json({ ok: false });
    if (imgRes.rows[0].drive_file_id) { try { await drive.files.delete({ fileId: imgRes.rows[0].drive_file_id }); } catch (e) { console.warn("Drive delete failed"); } }
    await pool.query("DELETE FROM gallery_images WHERE id=$1", [req.params.imageId]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false }); }
});

// 11. CONTACT & SEED
app.get("/contacts", authMiddleware, async (req, res) => {
  try { if (req.user.role !== "organizer") return res.status(403).json({ ok: false }); const result = await pool.query("SELECT * FROM contact_messages ORDER BY created_at DESC"); res.json({ ok: true, contacts: result.rows }); } catch (err) { res.status(500).json({ ok: false }); }
});

app.delete("/contacts/:id", authMiddleware, async (req, res) => {
  try { if (req.user.role !== "organizer") return res.status(403).json({ ok: false }); await pool.query("DELETE FROM contact_messages WHERE id=$1", [req.params.id]); res.json({ ok: true }); } catch (err) { res.status(500).json({ ok: false }); }
});

app.post("/api/contact", async (req, res) => {
  try { await pool.query("INSERT INTO contact_messages (name, email, message) VALUES ($1, $2, $3)", [req.body.name, req.body.email, req.body.message]); res.json({ ok: true }); } catch (err) { res.status(500).json({ ok: false }); }
});

app.post("/api/seed/create-user", async (req, res) => {
  if (req.headers["x-seed-secret"] !== process.env.SEED_API_SECRET) return res.status(403).json({ ok: false });
  const hash = await bcrypt.hash(req.body.password, 10);
  if (req.body.type === "organizer") await pool.query("INSERT INTO organizers (username, password_hash) VALUES ($1,$2)", [req.body.username, hash]);
  res.json({ ok: true });
});
// UPDATED: Route changed to '/update/:id' to avoid conflicts
app.put("/api/events/update/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { name, amount, description, endDate, languages, type, groupSize } = req.body;
  const id = req.params.id;
  try {
    const slug = name.toLowerCase().replace(/\s+/g, "-").slice(0, 80);
    const langString = Array.isArray(languages) ? languages.join(',') : (languages || "");

    await pool.query(
      `UPDATE events SET 
        name=$1, 
        slug=$2, 
        entry_amount=$3, 
        description=$4, 
        end_date=$5, 
        allowed_languages=$6, 
        participation_type=$7, 
        max_group_size=$8 
       WHERE id=$9`,
      [name, slug, amount, description || "", endDate, langString, type || "Solo", groupSize || 1, id]
    );
    res.json({ ok: true, message: "Event Updated" });
  } catch (err) {
    console.error("Update Event Error:", err);
    res.status(500).json({ ok: false, message: "Failed to update event" });
  }
});
import crypto from "crypto";

// Memory store for tokens: { "token123": { email: "...", expiresAt: 12345 } }
const resetTokens = new Map();

// --- 1. REQUEST LINK ---
app.post("/api/auth/request-forgot-password", async (req, res) => {
  const { identifier } = req.body;
  try {
    const userRes = await pool.query(
      "SELECT email, username, last_password_reset FROM organizers WHERE username = $1 OR phone = $2",
      [identifier, identifier]
    );

    if (userRes.rows.length === 0) return res.status(404).json({ ok: false, message: "User not found." });

    const user = userRes.rows[0];

    // 15-Day Cooldown Check
    const lastReset = new Date(user.last_password_reset);
    const diffDays = Math.ceil((new Date() - lastReset) / (1000 * 60 * 60 * 24));
    if (diffDays < 15) {
      return res.status(403).json({ ok: false, message: `Wait ${15 - diffDays} more days to reset.` });
    }

    // Generate Single-Use Token
    const token = crypto.randomBytes(32).toString("hex");
    resetTokens.set(token, { email: user.email, expiresAt: Date.now() + 15 * 60 * 1000 });

    const resetLink = `http://quantumquirksuoa.co.in/login/reset-password.html?token=${token}`;
    await resend.emails.send({
      from: EMAIL_FROM,
      to: user.email,
      subject: "One-Time Password Reset Link",
      html: `<p>Your single-use link: <a href="${resetLink}">${resetLink}</a></p>`
    });

    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false }); }
});

// --- 2. VALIDATE TOKEN (Called when page loads) ---
app.get("/api/auth/validate-reset-token/:token", (req, res) => {
  const { token } = req.params;
  const record = resetTokens.get(token);

  if (!record || Date.now() > record.expiresAt) {
    if (record) resetTokens.delete(token); // Cleanup expired
    return res.status(400).json({ ok: false, message: "Link invalid or expired." });
  }
  res.json({ ok: true });
});

// --- 3. EXECUTE RESET (Consumes the token) ---
app.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  const record = resetTokens.get(token);

  if (!record) return res.status(400).json({ ok: false, message: "This link has already been used." });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("UPDATE organizers SET password = $1, last_password_reset = NOW() WHERE email = $2", [hashedPassword, record.email]);

    // CONSUME TOKEN: Delete it so it can never be used again
    resetTokens.delete(token);

    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false }); }
});
// 1. Fetch all Staff (Organizers and Volunteers)
// This queries both tables and combines them
app.get("/api/admin/staff", authMiddleware, requireRole("organizer"), async (req, res) => {
  try {
      // We select the basic info. 
      // Note: Postgres doesn't allow 'decrypting' bcrypt, so passwords aren't sent.
      const orgs = await pool.query("SELECT id, name, email, phone, username, 'organizer' as role FROM organizers");
      const vols = await pool.query("SELECT id, name, email, phone, vol_id as username, 'volunteer' as role FROM volunteers");
      
      res.json({ ok: true, staff: [...orgs.rows, ...vols.rows] });
  } catch (err) {
      console.error(err);
      res.status(500).json({ ok: false, message: "Failed to fetch staff" });
  }
});

// 2. Delete Staff Member
app.delete("/api/admin/staff/:role/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { role, id } = req.params;
  try {
      const table = role === 'organizer' ? 'organizers' : 'volunteers';
      await pool.query(`DELETE FROM ${table} WHERE id = $1`, [id]);
      res.json({ ok: true, message: "Staff member removed" });
  } catch (err) {
      res.status(500).json({ ok: false, message: "Delete failed" });
  }
});

// 3. Update Staff Info (Not Username/Password)
app.put("/api/admin/staff/:role/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { role, id } = req.params;
  const { name, email, phone } = req.body;
  try {
      const table = role === 'organizer' ? 'organizers' : 'volunteers';
      await pool.query(
          `UPDATE ${table} SET name=$1, email=$2, phone=$3 WHERE id=$4`,
          [name, email, phone, id]
      );
      res.json({ ok: true, message: "Info updated" });
  } catch (err) {
      res.status(500).json({ ok: false });
  }
});
// --- FIND AND REPLACE ALL "/api/verify-code" ROUTES WITH THIS ONE ---

app.post("/api/recheck/verify-code", authMiddleware, async (req, res) => {
  let { code } = req.body;
  if (!code) return res.status(400).json({ ok: false, message: "Code required" });
  code = code.trim().toUpperCase();

  const client = await pool.connect();
  try {
    const pRes = await client.query("SELECT id, event_id, name, email FROM participants WHERE code=$1", [code]);
    if (pRes.rows.length === 0) return res.status(404).json({ ok: false, message: "Code not found in database." });
    const user = pRes.rows[0];

    const existing = await client.query("SELECT pc_number FROM allocations WHERE participant_id=$1", [user.id]);
    if (existing.rows.length > 0) {
      return res.json({ ok: true, alreadyAllocated: true, pc: existing.rows[0].pc_number, name: user.name });
    }

    await client.query("BEGIN");
    const pc = await allocatePcForParticipant(client, user.id, user.event_id);
    const ev = await client.query("SELECT name FROM events WHERE id=$1", [user.event_id]);
    await client.query("COMMIT");

    await resend.emails.send({
      from: EMAIL_FROM, to: user.email, subject: `[STATION ASSIGNED] ${ev.rows[0].name}`,
      html: getPcAllocationHtml(ev.rows[0].name, user.name, `PC-${pc}`)
    });

    res.json({ ok: true, alreadyAllocated: false, pc, name: user.name });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ ok: false });
  } finally { client.release(); }
});


app.get("/api/volunteer/allocations", authMiddleware, async (req, res) => {
  const r = await pool.query(`SELECT a.pc_number, p.name, p.phone, p.code FROM allocations a JOIN participants p ON a.participant_id = p.id ORDER BY a.allocated_at DESC`);
  res.json({ ok: true, allocations: r.rows });
});
// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ Server listening on http://localhost:${PORT}`));