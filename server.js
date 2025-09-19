// server.js (ESM)
import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import Joi from "joi";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import QRCode from "qrcode"; 

dotenv.config();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_prod";

// ---------- Postgres (Neon) ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- Create tables if not exists ----------
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
        entry_Amount INT NOT NULL,
        description TEXT,
        start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_date TIMESTAMP NOT NULL
      );
CREATE TABLE if not exists gallery_images (
  id SERIAL PRIMARY KEY,
  event_id INT REFERENCES events(id) ON DELETE CASCADE,
  image_path TEXT NOT NULL,
  description TEXT,
  event_date DATE
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
  code VARCHAR(16) UNIQUE, -- TECH####
  payment_id VARCHAR(100),
  order_id VARCHAR(100),
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
    `);
    console.log("✅ DB tables ensured");
  } catch (err) {
    console.error("DB init error:", err);
    process.exit(1);
  }
})();

// ---------- Express setup ----------
const app = express();
app.use(helmet());
app.use(express.json());
app.use(
  cors({
    origin: ["https://quantumquirksuoa.co.in", "https://quantumquirksuoa.netlify.app"],
    credentials: true,
  })
);

// ---------- Nodemailer ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: process.env.SMTP_SECURE === "true" || Number(process.env.SMTP_PORT) === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ---------- OTP store ----------
const otpStore = new Map(); // { email: { code, expiresAt, verified } }
const OTP_EXP_MINUTES = Number(process.env.OTP_EXP_MINUTES || 10);

function createOTP(len = 6) {
  return Array.from({ length: len }, () => Math.floor(Math.random() * 10)).join("");
}
function setOTP(email, code) {
  otpStore.set(email.toLowerCase(), { code, expiresAt: Date.now() + OTP_EXP_MINUTES * 60 * 1000, verified: false });
}
function getOTP(email) {
  return otpStore.get((email || "").toLowerCase());
}
function clearOTP(email) {
  otpStore.delete((email || "").toLowerCase());
}

// ---------- Helpers ----------
function generateEnrollCode() {
  // returns 4 digit number as string, e.g. "3738"
  return String(Math.floor(1000 + Math.random() * 9000));
}

/**
 * Generate a unique "TECH####" code for the given event.
 * This checks DB before returning. Retries up to maxAttempts.
 */
// Generate unique code safely (outside transaction)
import { customAlphabet } from "nanoid";

// 5-char alphanumeric code
const nanoid = customAlphabet("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", 5);

async function generateUniqueCode(client, eventId) {
  for (let i = 0; i < 20; i++) { // try 20 times
    const code = "TECH" + nanoid();

    const res = await client.query(
      "SELECT id FROM participants WHERE event_id=$1 AND code=$2",
      [eventId, code]
    );

    if (res.rows.length === 0) {
      return code; // unique
    }
    // else, collision, retry
  }
  throw new Error("Unable to generate unique participant code after multiple attempts");
}



// ---------- Auth / JWT ----------
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "8h" });
}

function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization;
  if (!hdr) return res.status(401).json({ ok: false, message: "Authorization required" });
  const parts = hdr.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ ok: false, message: "Invalid auth header" });
  try {
    const data = jwt.verify(parts[1], JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, message: "Invalid token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ ok: false, message: "Forbidden: insufficient role" });
    next();
  };
}

// ---------- Validation Schemas ----------
const enrollSchema = Joi.object({
  name: Joi.string().min(2).max(120).required(),
  batch: Joi.string().min(1).max(50).required(),
  semester: Joi.string().min(1).max(50).required(),
  fatherName: Joi.string().min(2).max(120).required(),
  motherName: Joi.string().min(2).max(120).required(),
  gender: Joi.string().valid("Male", "Female", "Other").required(),
  email: Joi.string().email().required(),
  phone: Joi.string().pattern(/^[0-9]{10,15}$/).required(),
  preferredLanguage: Joi.string().min(1).max(50).required(),
  eventId: Joi.number().integer().required(),
});

// ---------- Routes ----------

// Health
app.get("/api/health", (req, res) => res.json({ ok: true }));

// ---------------- Check email availability ----------------
app.post("/api/check-email", async (req, res) => {
  const { email, eventId } = req.body;
  if (!email || !eventId) return res.status(400).json({ ok: false, message: "Email & eventId required" });

  try {
    const r = await pool.query(
      "SELECT id FROM participants WHERE email=$1 AND event_id=$2",
      [email, eventId]
    );
    if (r.rows.length > 0) {
      return res.json({ ok: false, message: "Email already registered for this event" });
    }
    return res.json({ ok: true, message: "Email available" });
  } catch (err) {
    console.error("check-email err:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ---------------- OTP ----------------
app.post("/api/otp/:eventId/send", async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ ok: false, message: "Email required" });

  const code = createOTP(6);
  setOTP(email, code);

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@Quantum Quirks.local>",
      to: email,
      subject: "Your Quantum Quirks OTP",
      html: `<p>Hello ${name || ""},</p><p>Your OTP code is:</p><h2>${code}</h2><p>It expires in ${OTP_EXP_MINUTES} minutes.</p>`
    });
    return res.json({ ok: true, message: "OTP sent" });
  } catch (err) {
    console.error("send OTP err:", err);
    return res.status(500).json({ ok: false, message: "Failed to send OTP" });
  }
});

app.post("/api/otp/:eventId/verify", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ ok: false, message: "Email & OTP required" });
  const record = getOTP(email);
  if (!record) return res.status(400).json({ ok: false, message: "OTP not found. Request again." });
  if (Date.now() > record.expiresAt) {
    clearOTP(email);
    return res.status(400).json({ ok: false, message: "OTP expired" });
  }
  if (record.code !== otp) return res.status(400).json({ ok: false, message: "Invalid OTP" });

  record.verified = true;
  otpStore.set(email.toLowerCase(), record);
  return res.json({ ok: true, message: "Email verified" });
});

// ---------------- Public Enroll (participant) ----------------// make sure to install: npm i qrcode



// import crypto from "crypto";
// import Razorpay from "razorpay"


// const RAZORPAY_KEY = process.env.RAZORPAY_KEY;
// const RAZORPAY_SECRET = process.env.RAZORPAY_SECRET;

// const razorpay = new Razorpay({
//   key_id: RAZORPAY_KEY,
//   key_secret: RAZORPAY_SECRET,
// });

// // -------------------- Create Razorpay Order --------------------
// app.post("/api/payment/order", async (req, res) => {
//   try {
//     const { eventId, email, participant } = req.body;

//     const eventRes = await pool.query(
//       "SELECT entry_amount FROM events WHERE id = $1",
//       [eventId]
//     );
//     if (!eventRes.rows.length) {
//       return res.status(400).json({ ok: false, message: "Event not found" });
//     }

//     const entryAmount = eventRes.rows[0].entry_amount;

//     const options = {
//       amount: entryAmount * 100,
//       currency: "INR",
//       receipt: `receipt_${Date.now()}`,
//       notes: { email, eventId, participant: JSON.stringify(participant) },
//     };

//     const order = await razorpay.orders.create(options);

//     res.json({
//       ok: true,
//       orderId: order.id,
//       amount: order.amount,
//       currency: order.currency,
//       key: RAZORPAY_KEY, // frontend ke liye
//     });
//   } catch (err) {
//     console.error("Payment Order Error:", err);
//     res.status(500).json({ ok: false, message: "Server error creating Razorpay order" });
//   }
// });

// // -------------------- Handle Payment Success --------------------
// app.post("/api/payment/success", async (req, res) => {
//   try {
//     const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

//     const body = razorpay_order_id + "|" + razorpay_payment_id;
//     const expectedSignature = crypto
//       .createHmac("sha256", RAZORPAY_SECRET)
//       .update(body.toString())
//       .digest("hex");

//     if (expectedSignature !== razorpay_signature) {
//       return res.status(400).json({ ok: false, message: "Invalid signature" });
//     }

//     const order = await razorpay.orders.fetch(razorpay_order_id);
//     const { email, eventId, participant } = order.notes;
//     const parsedParticipant = JSON.parse(participant);

//     const enrollRes = await fetch("http://localhost:5000/api/participants/enroll", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({
//         ...parsedParticipant,
//         email,
//         eventId,
//         paymentId: razorpay_payment_id,
//         orderId: razorpay_order_id,
//         paymentMode: "Razorpay",
//         txStatus: "SUCCESS",
//         signature: razorpay_signature,
//       }),
//     });

//     const enrollData = await enrollRes.json();

//     if (enrollRes.ok && enrollData.ok) {
//       return res.redirect(`/successful.html?code=${encodeURIComponent(enrollData.code)}`);
//     } else {
//       return res.redirect(`/failed.html?message=${encodeURIComponent(enrollData.message)}`);
//     }
//   } catch (err) {
//     console.error("Payment success error:", err);
//     res.status(500).send("Server error");
//   }
// });


app.post("/api/participants/enroll", async (req, res) => {
  try {
    const { error, value } = enrollSchema.validate(req.body);
    if (error) return res.status(400).json({ ok: false, message: error.message });

    const { email, eventId } = value;

    // ✅ OTP check
    const otpRec = getOTP(email);
    if (!otpRec || !otpRec.verified) {
      return res.status(400).json({ ok: false, message: "Please verify your email first." });
    }

    // ✅ Fetch event details
    const ev = await pool.query("SELECT id, name FROM events WHERE id=$1", [eventId]);
    if (ev.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "Event not found" });
    }
    const event = ev.rows[0];

    // ✅ Check duplicate registration
    const dup = await pool.query(
      "SELECT id FROM participants WHERE event_id=$1 AND email=$2",
      [eventId, email]
    );
    if (dup.rows.length > 0) {
      return res.status(400).json({ ok: false, message: "Email already registered for this event" });
    }

    // ✅ Insert participant
    const client = await pool.connect();
    let finalCode = null;
    try {
      await client.query("BEGIN");
      finalCode = await generateUniqueCode(client, eventId);

      await client.query(
        `INSERT INTO participants
          (event_id, name, batch, semester, father_name, mother_name, gender, email, phone, preferred_language, code, payment)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending')`, // payment = pending
        [
          eventId,
          value.name,
          value.batch,
          value.semester,
          value.fatherName,
          value.motherName,
          value.gender,
          value.email,
          value.phone,
          value.preferredLanguage,
          finalCode
        ]
      );

      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Enroll transaction err:", err);
      return res.status(500).json({ ok: false, message: "Enrollment failed" });
    } finally {
      client.release();
    }

    // ✅ Generate QR Code
    const qrBuffer = await QRCode.toBuffer(finalCode, {
      type: "png",
      width: 200,
      margin: 2,
      color: { dark: "#000000", light: "#ffffff" },
    });

    // ✅ Send confirmation email
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@quantumquirks.local>",
        to: email,
        subject: `Enrollment Confirmed - ${event.name}`,
        html:`<table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:400px; font-family: Arial, sans-serif; background:#ffffff; border-radius:8px; overflow:hidden;">
  
  <!-- Header -->
  <tr>
    <td align="center" bgcolor="#4f46e5" style="padding:20px; color:#ffffff;">
      <h1 style="margin:0; font-size:24px;">Quantum Quirks</h1>
      <h2 style="margin:5px 0; font-size:18px; font-weight:normal;">Enrollment Confirmed</h2>
    </td>
  </tr>

  <!-- Event Details -->
  <tr>
    <td style="padding:20px; font-size:14px; line-height:20px; color:#333333; border-bottom:1px solid #eeeeee;">
      <h3 style="margin-bottom:10px; color:#4f46e5; font-size:16px; text-align:center;">Event Details</h3>
      <p style="text-align:center;"><b>Event:</b> ${event.name}</p>
      <p style="text-align:center;"><b>Participant:</b> ${value.name}</p>
      <p style="text-align:center;"><b>Email:</b> ${value.email}</p>
      <p style="text-align:center;"><b>Phone:</b> ${value.phone}</p>
    </td>
  </tr>

  <!-- Code & QR -->
  <tr>
    <td align="center" style="padding:20px; font-size:14px; color:#333333; border-bottom:1px solid #eeeeee;">
      <h3 style="margin-bottom:10px; color:#4f46e5; font-size:16px;">Your Code</h3>
      <p style="font-size:20px; font-weight:bold; color:#111111; margin:0;">${finalCode}</p>
      <img src="cid:qrCodeImage" alt="QR Code" width="150" height="150" style="margin-top:10px; display:block; margin-left:auto; margin-right:auto;" />
    </td>
  </tr>

  <!-- Footer -->
  <tr>
    <td align="center" bgcolor="#f9fafb" style="padding:15px; font-size:12px; color:#555555;">
      Thank you for enrolling in <b>${event.name}</b>!<br>
      Please keep this email safe and show your QR code or unique code at the event entrance.
    </td>
  </tr>

</table>
`,
        attachments: [{ filename: "qrcode.png", content: qrBuffer, cid: "qrCodeImage" }],
      });
    } catch (mailErr) {
      console.warn("Email send after enroll failed:", mailErr);
    }

    clearOTP(email);
    return res.json({ ok: true, message: "Enrollment success", code: finalCode });
  } catch (err) {
    console.error("Enroll err:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});




// ---------------- Organizer & Volunteer login ----------------
app.post("/api/organizer/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length !== 8) return res.status(400).json({ ok: false, message: "Provide valid 8-char username and password" });

  try {
    const r = await pool.query("SELECT id, password FROM organizers WHERE username=$1", [username]);
    if (r.rows.length === 0) return res.status(401).json({ ok: false, message: "Invalid credentials" });
    const row = r.rows[0];
    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const token = signToken({ id: row.id, username, role: "organizer" });
    return res.json({ ok: true, role: "organizer", token });
  } catch (err) {
    console.error("organizer login err:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.post("/api/volunteer/login", async (req, res) => {
  const { volId, password } = req.body;
  if (!volId || !password || volId.length !== 6) return res.status(400).json({ ok: false, message: "Provide valid 6-char volunteer id & password" });

  try {
    const r = await pool.query("SELECT id, password_hash FROM volunteers WHERE vol_id=$1", [volId]);
    if (r.rows.length === 0) return res.status(401).json({ ok: false, message: "Invalid credentials" });
    const row = r.rows[0];
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const token = signToken({ id: row.id, volId, role: "volunteer" });
    return res.json({ ok: true, role: "volunteer", token });
  } catch (err) {
    console.error("vol login err:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ---------------- Events (organizer) ----------------
app.post("/api/events", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { name, amount, description, endDate } = req.body;
  if (!name || !endDate) return res.status(400).json({ ok: false, message: "name & endDate required" });

  try {
    const slug = name.toLowerCase().replace(/\s+/g, "-").slice(0, 80);

    // 👇 corrected column name entry_amount
    const r = await pool.query(
      "INSERT INTO events (slug, name, entry_Amount, description, end_date) VALUES ($1,$2,$3,$4,$5) RETURNING *",
      [slug, name, amount, description || "", endDate]
    );

    return res.json({ ok: true, event: r.rows[0] });
  } catch (err) {
    console.error("create event err:", err);
    return res.status(500).json({ ok: false, message: "Failed to create event" });
  }
});

app.get("/contacts", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "organizer") {
      return res.status(403).json({ ok: false, message: "Access denied" });
    }

    const result = await pool.query(
      "SELECT id, name, email, message, created_at FROM contact_messages ORDER BY created_at DESC"
    );

    res.json({ ok: true, contacts: result.rows });
  } catch (err) {
    console.error("Error fetching contacts:", err);
    res.status(500).json({ ok: false, message: "Server error" });
  }
});

// Delete a contact by ID
app.delete("/contacts/:id", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "organizer") {
      return res.status(403).json({ ok: false, message: "Access denied" });
    }

    const { id } = req.params;
    await pool.query("DELETE FROM contact_messages WHERE id=$1", [id]);

    res.json({ ok: true, message: "Contact deleted" });
  } catch (err) {
    console.error("Error deleting contact:", err);
    res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.get("/api/events", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM events ORDER BY start_date DESC");
    return res.json({ ok: true, events: r.rows });
  } catch (err) {
    console.error("get events err:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch events" });
  }
});

// (remaining routes unchanged - allocations, organizer participant endpoints etc.)
// For brevity I assume the rest of your file remains as previously (allocations, verify-code, organizer allocate, seed user, etc.)
// If you'd like, I can paste the remainder with the same allocation logic you had.





// POST /api/organizer/volunteer
app.post("/api/organizer/volunteer", authMiddleware, requireRole("organizer"), async (req, res) => {
  try {
    const { name, email, phone, username, password } = req.body;

    if (!name || !email || !phone || !username || !password)
      return res.status(400).json({ ok: false, message: "All fields are required" });

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ ok: false, message: "Invalid email format" });

    // Check if volunteer already exists
    const existing = await pool.query("SELECT * FROM volunteers WHERE vol_id=$1", [username]);
    if (existing.rows.length > 0)
      return res.status(400).json({ ok: false, message: "Volunteer already registered" });

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Insert into DB
    const result = await pool.query(
      `INSERT INTO volunteers (vol_id, password_hash, name, email, phone) 
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [username, hashed, name, email, phone]
    );

    console.log("Sending email to:", email);

    // Send welcome email
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@Quantum Quirks.local>",
      to: email,
      subject: "Welcome to Quantum Quirks! 🎉",
      html: `
        <h2>Hello, ${name}!</h2>
        <p>Welcome aboard as a volunteer for our Quantum Quirks event.</p>
        <p>Here are your credentials:</p>
        <ul>
          <li><b>Volunteer ID / Username:</b> ${username}</li>
          <li><b>Email:</b> ${email}</li>
          <li><b>Password:</b> ${password}</li>
        </ul>
        <p>Please <b>keep this information safe</b> and log in to the volunteer dashboard to start managing participants.</p>
        <p>We are excited to have you with us! 🚀</p>
        <p>— <i>Quantum Quirks Team</i></p>
      `
    });

    res.json({ ok: true, volunteer: result.rows[0], message: "Volunteer added and email sent!" });

  } catch (err) {
    console.error("Volunteer route error:", err);
    res.status(500).json({ ok: false, message: "Server error" });
  }
});


// Add Organizer (Admin only)
app.post("/api/admin/organizer", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { name, email, phone, username, password } = req.body;

  if(!name || !email || !phone || !username || !password){
    return res.status(400).json({ ok: false, message: "All fields required" });
  }
  if(username.length !== 8){
    return res.status(400).json({ ok: false, message: "Username must be 8 characters" });
  }

  try {
    // hash password
    const hashed = await bcrypt.hash(password, 10);

    // check for duplicates
    const dup = await pool.query("SELECT id FROM organizers WHERE username=$1 OR email=$2", [username, email]);
    if(dup.rows.length > 0){
      return res.status(400).json({ ok: false, message: "Username or Email already exists" });
    }

    // insert organizer
    const insert = await pool.query(
      `INSERT INTO organizers (name, email, phone, username, password, role) 
       VALUES ($1,$2,$3,$4,$5,'organizer') RETURNING id, name, email, username, role`,
      [name, email, phone, username, hashed]
    );

    console.log("Sending organizer email to:", email);

    // send styled HTML email
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || "Quantum Quarks <no-reply@quantumquarks.com>",
      to: email,
      subject: "You have been added as Organizer 🎉",
      html: `
        <div style="font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px;">
          <div style="max-width: 600px; margin: auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
            <h2 style="color: #4f46e5; text-align: center;">Welcome to Quantum Quarks 🚀</h2>
            <p>Hello <b>${name}</b>,</p>
            <p>We are excited to inform you that you have been added as an <b>Organizer</b> for our event.</p>
            <p>Here are your login credentials:</p>
            <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Username</b></td><td style="padding: 8px; border: 1px solid #ddd;">${username}</td></tr>
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Email</b></td><td style="padding: 8px; border: 1px solid #ddd;">${email}</td></tr>
              <tr><td style="padding: 8px; border: 1px solid #ddd;"><b>Password</b></td><td style="padding: 8px; border: 1px solid #ddd;">${password}</td></tr>
            </table>
            <p style="color: #d32f2f;">⚠️ Please keep this information safe and do not share it with anyone.</p>
            <p>You can now log in to your organizer dashboard and start managing events and participants.</p>
            <p style="margin-top: 20px;">Best regards,<br/><i>The Quantum Quarks Team</i></p>
          </div>
        </div>
      `
    });

    return res.json({ ok: true, organizer: insert.rows[0], message: "Organizer added and email sent!" });

  } catch(err) {
    console.error("add organizer error:", err);
    res.status(500).json({ ok: false, message: "Failed to add organizer" });
  }
});


// ---------------- Events (organizer) ----------------
app.post("/api/events", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { name, description, endDate } = req.body;
  if (!name || !endDate) return res.status(400).json({ ok: false, message: "name & endDate required" });

  try {
    const slug = name.toLowerCase().replace(/\s+/g, "-").slice(0, 80);
    const r = await pool.query("INSERT INTO events (slug, name, description, end_date) VALUES ($1,$2,$3,$4) RETURNING *", [slug, name, description || "", endDate]);
    return res.json({ ok: true, event: r.rows[0] });
  } catch (err) {
    console.error("create event err:", err);
    return res.status(500).json({ ok: false, message: "Failed to create event" });
  }
});

app.get("/api/events", async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM events ORDER BY start_date DESC");
    return res.json({ ok: true, events: r.rows });
  } catch (err) {
    console.error("get events err:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch events" });
  }
});

// ---------------- Organizer: add / edit participant ----------------
app.post("/api/organizer/participant", authMiddleware, requireRole("organizer"), async (req, res) => {
  const schema = Joi.object({
    eventId: Joi.number().integer().required(),
    name: Joi.string().min(2).required(),
    fatherName: Joi.string().allow("", null),
    motherName: Joi.string().allow("", null),
    gender: Joi.string().valid("Male", "Female", "Other").required(),
    email: Joi.string().email().required(),
    phone: Joi.string().required(),
    preferredLanguage: Joi.string().required()
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ ok: false, message: error.message });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const ev = await client.query("SELECT id FROM events WHERE id=$1", [value.eventId]);
    if (ev.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, message: "Event not found" }); }

    const dup = await client.query("SELECT id FROM participants WHERE event_id=$1 AND email=$2", [value.eventId, value.email]);
    if (dup.rows.length > 0) { await client.query("ROLLBACK"); return res.status(400).json({ ok: false, message: "Email already registered for event" }); }

    // generate unique code
    const code = await generateUniqueCode(client,value.eventId);

    const insert = await client.query(
      `INSERT INTO participants (event_id, name, father_name, mother_name, gender, email, phone, preferred_language, code)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [value.eventId, value.name, value.fatherName, value.motherName, value.gender, value.email, value.phone, value.preferredLanguage, code]
    );
    await client.query("COMMIT");

    // send confirmation mail
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@Quantum Quirks.local>",
        to: value.email,
        subject: "You were added to Quantum Quirks by Organizer",
        html: `<p>Hello ${value.name},</p><p>You were added to event. Your code: <b>${code}</b></p>`
      });
    } catch (mailErr) { console.warn("organizer add participant mail failed", mailErr); }

    return res.json({ ok: true, participant: insert.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK");
    
    console.error("organizer add participant err:", err);
    return res.status(500).json({ ok: false, message: "Failed to add participant" });
  } finally {
    client.release();
  }
});

app.put("/api/organizer/participant/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  const id = Number(req.params.id);
  const { name, fatherName, motherName, gender, phone, preferredLanguage } = req.body;
  try {
    const r = await pool.query(
      `UPDATE participants SET name=$1, father_name=$2, mother_name=$3, gender=$4, phone=$5, preferred_language=$6 WHERE id=$7 RETURNING *`,
      [name, fatherName, motherName, gender, phone, preferredLanguage, id]
    );
    if (r.rows.length === 0) return res.status(404).json({ ok: false, message: "Participant not found" });
    return res.json({ ok: true, participant: r.rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(400).json({ ok: false, message: "Preferred language conflict" });
    console.error("edit participant err:", err);
    return res.status(500).json({ ok: false, message: "Failed to edit participant" });
  }
});

// ---------------- List participants (event wise) ----------------
app.get("/api/events/:id/participants", authMiddleware, async (req, res) => {
  const eventId = Number(req.params.id);
  try {
    const r = await pool.query("SELECT * FROM participants WHERE event_id=$1 ORDER BY id DESC", [eventId]);
    return res.json({ ok: true, participants: r.rows });
  } catch (err) {
    console.error("list participants err:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch participants" });
  }
});

// ---------------- Allocation (verify code and allocate PC) -----------
// ---------------- Allocation (verify code and allocate PC) -----------

// 🔹 Updated allocation: ensure no adjacent participants have same language
async function allocatePcForParticipant(client, participantId, eventId) {
  // check if already allocated
  const existing = await client.query(
    "SELECT pc_number FROM allocations WHERE participant_id=$1",
    [participantId]
  );
  if (existing.rows.length > 0) return existing.rows[0].pc_number;

  // get participant's language
  const langRes = await client.query(
    "SELECT preferred_language FROM participants WHERE id=$1",
    [participantId]
  );
  if (langRes.rows.length === 0) throw new Error("Participant not found for allocation");
  const myLang = langRes.rows[0].preferred_language;

  // get all allocations for this event
  const usedRes = await client.query(
    `SELECT a.pc_number, p.preferred_language
     FROM allocations a
     JOIN participants p ON a.participant_id = p.id
     WHERE a.event_id=$1
     ORDER BY a.pc_number ASC`,
    [eventId]
  );

  const used = usedRes.rows;

  let pc = 1;
  while (true) {
    // check if pc already taken
    if (used.find(u => u.pc_number === pc)) {
      pc++;
      continue;
    }

    // check neighbor languages
    const left = used.find(u => u.pc_number === pc - 1);
    const right = used.find(u => u.pc_number === pc + 1);

    if ((left && left.preferred_language === myLang) ||
        (right && right.preferred_language === myLang)) {
      // skip this pc and try next
      pc++;
      continue;
    }

    // ✅ Found valid PC
    break;
  }

  await client.query(
    "INSERT INTO allocations (event_id, participant_id, pc_number) VALUES ($1,$2,$3)",
    [eventId, participantId, pc]
  );

  return pc;
}


app.post("/api/verify-code", authMiddleware, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ ok: false, message: "code required" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // find participant (lock)
    const p = await client.query("SELECT id, event_id, email, name FROM participants WHERE code=$1 FOR UPDATE", [code]);
    if (p.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, message: "Participant not found" }); }
    const participant = p.rows[0];

    // allocate pc
    const pc = await allocatePcForParticipant(client, participant.id, participant.event_id);

    await client.query("COMMIT");

    // email participant about allocation
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@Quantum Quirks.local>",
        to: participant.email,
        subject: "Your PC Allocation — Quantum Quirks",
        html: `<p>Hi ${participant.name},</p><p>Your PC number for the event: <b>${pc}</b></p>`
      });
    } catch (mailErr) { console.warn("allocation mail err", mailErr); }

    return res.json({ ok: true, message: "Verified & allocated", pc });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("verify-code err:", err);
    return res.status(500).json({ ok: false, message: "Allocation failed" });
  } finally {
    client.release();
  }
});

// ---------------- Organizer direct allocate (by participant id) ----------
app.post("/api/organizer/allocate", authMiddleware, requireRole("organizer"), async (req, res) => {
  const { participantId } = req.body;
  if (!participantId) return res.status(400).json({ ok: false, message: "participantId required" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const pRes = await client.query("SELECT id, event_id, email, name FROM participants WHERE id=$1 FOR UPDATE", [participantId]);
    if (pRes.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ ok: false, message: "Participant not found" }); }
    const participant = pRes.rows[0];

    const pc = await allocatePcForParticipant(client, participant.id, participant.event_id);

    await client.query("COMMIT");

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@Quantum Quirks.local>",
        to: participant.email,
        subject: "PC Allocated by Organizer",
        html: `<p>Hi ${participant.name},</p><p>Your PC number: <b>${pc}</b></p>`
      });
    } catch (mailErr) { console.warn("organizer allocate mail err", mailErr); }

    return res.json({ ok: true, message: "Allocated", pc });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("organizer allocate err:", err);
    return res.status(500).json({ ok: false, message: "Allocation failed" });
  } finally {
    client.release();
  }
});
// DELETE Event (and all participants inside)
app.delete("/api/events/:id",authMiddleware, requireRole("organizer"), async (req, res) => {
  const eventId = Number(req.params.id);
  if (!eventId) return res.status(400).json({ ok: false, message: "Invalid event ID" });

  try {
    // Delete participants first
    await pool.query("DELETE FROM participants WHERE event_id = $1", [eventId]);
    // Delete the event
    const result = await pool.query("DELETE FROM events WHERE id = $1 RETURNING *", [eventId]);
    if (!result.rows.length) return res.status(404).json({ ok: false, message: "Event not found" });
    res.json({ ok: true, message: "Event and its participants deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: "Server error" });
  }
});

// DELETE Participant by ID
app.delete("/api/participants/:id",authMiddleware, requireRole("organizer"), async (req, res) => {
  const participantId = Number(req.params.id);
  if (!participantId) return res.status(400).json({ ok: false, message: "Invalid participant ID" });

  try {
    const result = await pool.query("DELETE FROM participants WHERE id = $1 RETURNING *", [participantId]);
    if (!result.rows.length) return res.status(404).json({ ok: false, message: "Participant not found" });
    res.json({ ok: true, message: "Participant deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: "Server error" });
  }
});


// ---------------- Admin utility: create organizer or volunteer (secure — for setup) ----------
app.post("/api/seed/create-user", async (req, res) => {
  // For safety: require an env secret as basic guard
  if (req.headers["x-seed-secret"] !== process.env.SEED_API_SECRET) {
    return res.status(403).json({ ok: false, message: "Forbidden" });
  }
  const { type, username, password } = req.body;
  if (!type || !username || !password) return res.status(400).json({ ok: false, message: "type/username/password required" });
  try {
    const hash = await bcrypt.hash(password, 10);
    if (type === "organizer") {
      await pool.query("INSERT INTO organizers (username, password_hash) VALUES ($1,$2) ON CONFLICT DO NOTHING", [username, hash]);
      return res.json({ ok: true, message: "Organizer seeded" });
    } else if (type === "volunteer") {
      await pool.query("INSERT INTO volunteers (vol_id, password_hash) VALUES ($1,$2) ON CONFLICT DO NOTHING", [username, hash]);
      return res.json({ ok: true, message: "Volunteer seeded" });
    } else return res.status(400).json({ ok: false, message: "type must be organizer|volunteer" });
  } catch (err) {
    console.error("seed create user err:", err);
    return res.status(500).json({ ok: false, message: "Failed to seed user" });
  }
});


import multer from "multer";
import path from "path";



// ensure static uploads folder exists


// ---------------- Load participants by event + language ----------------
// ---------------- Participants (Organizer view) ----------------

// Get all participants with event name
app.get("/api/participants", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT p.id, p.name, p.email, p.preferred_language AS language,
             e.name AS event_name
      FROM participants p
      JOIN events e ON p.event_id = e.id
      ORDER BY p.id ASC
    `);
    return res.json({ ok: true, participants: r.rows });
  } catch (err) {
    console.error("get participants err:", err);
    return res.status(500).json({ ok: false, message: "Failed to fetch participants" });
  }
});

// Update participant details
app.put("/api/participants/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email, language, event_name } = req.body;

  if (!name || !email || !language || !event_name) {
    return res.status(400).json({ ok: false, message: "All fields required" });
  }

  try {
    // find event id by event_name
    const ev = await pool.query("SELECT id FROM events WHERE name=$1", [event_name]);
    if (ev.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "Event not found" });
    }
    const eventId = ev.rows[0].id;

    // update participant
    const r = await pool.query(
      `UPDATE participants
       SET name=$1, email=$2, preferred_language=$3, event_id=$4
       WHERE id=$5 RETURNING *`,
      [name, email, language, eventId, id]
    );

    if (r.rows.length === 0) {
      return res.status(404).json({ ok: false, message: "Participant not found" });
    }

    // send notification email
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || "Quantum Quirks <no-reply@QuantumQuirks.local>",
        to: email,
        subject: "Your Details Have Been Updated",
        html: `
          <p>Hello ${name},</p>
          <p>Your registration details have been updated:</p>
          <ul>
            <li><b>Name:</b> ${name}</li>
            <li><b>Email:</b> ${email}</li>
            <li><b>Preferred Language:</b> ${language}</li>
            <li><b>Event:</b> ${event_name}</li>
          </ul>
          <p>If you didn’t request this change, please contact the organizers.</p>
        `
      });
    } catch (mailErr) {
      console.warn("update notify mail failed:", mailErr);
    }

    return res.json({ ok: true, participant: r.rows[0] });
  } catch (err) {
    console.error("update participant err:", err);
    return res.status(500).json({ ok: false, message: "Failed to update participant" });
  }
});

// ---------------- Update participant ----------------
app.put("/api/participants/:id", authMiddleware, requireRole("organizer"), async (req, res) => {
  const participantId = Number(req.params.id); // Get ID from URL
  const { name, email, language } = req.body; // No 'id' in body

  if (!name || !email || !language) {
    return res.status(400).json({ ok: false, message: "All fields required" });
  }

  try {
    const result = await pool.query(
      `UPDATE participants 
       SET name = $1, email = $2, preferred_language = $3
       WHERE id = $4
       RETURNING id, name, email, preferred_language AS "preferredLanguage"`,
      [name, email, language, participantId] // use participantId from URL
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ ok: false, message: "Participant not found" });
    }

    res.json({ ok: true, participant: result.rows[0] });
  } catch (err) {
    console.error("Update participant error:", err);
    res.status(500).json({ ok: false, message: "Failed to update participant" });
  }
});


import { fileURLToPath } from "url";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve files from backend/public/gallery
// Serve gallery images with proper CORS headers
app.use(
  "/gallery",
  (req, res, next) => {
    // Allow your frontend domain
    res.setHeader("Access-Control-Allow-Origin", "http://localhost:5500");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin"); // <-- key fix
    next();
  },
  express.static(path.join(__dirname, "public/gallery"))
);


// Setup Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/gallery"); // folder must exist
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// POST /api/organizer/gallery/:eventId
app.post(
  "/api/organizer/gallery/:eventId",
  authMiddleware,
  requireRole("organizer"),
  upload.single("image"),
  async (req, res) => {
    try {
      const eventId = Number(req.params.eventId);
      if (!req.file) return res.status(400).json({ ok: false, message: "No image uploaded" });

      const description = req.body.description || "";
      // Store relative path to match static route
      const imagePath = `/gallery/${req.file.filename}`;

      const result = await pool.query(
        `INSERT INTO gallery_images (event_id, image_path, description, event_date)
         VALUES ($1, $2, $3, (SELECT end_date FROM events WHERE id=$1))
         RETURNING id, event_id, image_path, description, event_date`,
        [eventId, imagePath, description]
      );

      res.json({ ok: true, message: "Image uploaded successfully", image: result.rows[0] });
    } catch (err) {
      console.error("Gallery upload error:", err);
      res.status(500).json({ ok: false, message: "Upload failed" });
    }
  }
);



// GET /api/gallery/:eventId
// GET /api/gallery/:eventId
// Gallery API (fetch images for an event)
app.get("/api/gallery/:eventId", async (req, res) => {
  const eventId = Number(req.params.eventId);

  try {
    const result = await pool.query(
      `SELECT id, event_id, image_path, description, event_date
       FROM gallery_images
       WHERE event_id = $1
       ORDER BY id ASC`,
      [eventId]
    );

    // Return images with the same path used in static route
    const images = result.rows.map(row => ({
      image_path: row.image_path,  // e.g., "/gallery/1757767320194.jpg"
      description: row.description || ""
    }));

    res.json({ ok: true, images });
  } catch (err) {
    console.error("Gallery fetch error:", err);
    res.status(500).json({ ok: false, images: [], error: "Failed to fetch gallery" });
  }
});

app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ ok: false, error: "All fields are required" });
    }

    // Insert into database
    const query = `
      INSERT INTO contact_messages (name, email, message, created_at)
      VALUES ($1, $2, $3, NOW()) RETURNING id
    `;
    const values = [name, email, message];
    const result = await pool.query(query, values);

    console.log("📩 New contact saved:", result.rows[0]);

    return res.json({ ok: true, msg: "Message saved successfully!" });
  } catch (err) {
    console.error("❌ Error saving contact:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});



// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ Server listening on http://localhost:${PORT}`));
