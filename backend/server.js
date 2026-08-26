require('dotenv').config();
const express = require('express');
const path = require('path');
const connectDB = require('./config/db');

// ── Route imports ─────────────────────────────────────────────
const adminRoutes     = require('./routes/admin');
const instituteRoutes = require('./routes/institute');
const authorityRoutes = require('./routes/authority');
const authRoutes      = require('./routes/auth');

// ── Connect to MongoDB ────────────────────────────────────────
connectDB();

const app = express();

// ── Middleware ────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Static App Serving ────────────────────────────────────────
// Serve dedicated sub-applications
app.use('/admin-app', express.static(path.join(__dirname, '../frontend/admin')));
app.use('/institute-app', express.static(path.join(__dirname, '../frontend/institute')));
app.use('/authority-app', express.static(path.join(__dirname, '../frontend/authority')));
app.use(express.static(path.join(__dirname, '../frontend')));

// ── Health check ──────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString(), system: 'VaultO Security Core v2.0' });
});

// ── Application Entrypoint Routes ─────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/index.html'));
});

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/login.html'));
});

app.get('/institute', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/institute/index.html'));
});

app.get('/institute/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/institute/login.html'));
});

app.get('/authority', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/authority/scanner.html'));
});

// ── API Routes (Namespaced & Backward Compatible) ─────────────
app.use('/admin',     adminRoutes);
app.use('/api/admin', adminRoutes);

app.use('/institute',     instituteRoutes);
app.use('/api/institute', instituteRoutes);

app.use('/authority',     authorityRoutes);
app.use('/api/authority', authorityRoutes);

app.use('/',          authRoutes);
app.use('/api/auth',  authRoutes);

const InstituteModel = require('./models/Institute');
const PaperModel = require('./models/Paper');

// ─────────────────────────────────────────────────────────────
// GET /institutes (Backward-compatibility)
// ─────────────────────────────────────────────────────────────
app.get('/institutes', async (req, res) => {
  try {
    const institutes = await InstituteModel.find({});
    const data = institutes.map(inst => ({
      instId: inst.instituteId,
      name: inst.name || inst.instituteId,
      email: inst.email,
      district: inst.district || 'General',
      status: inst.status || 'active',
      lastLogin: inst.lastLoginAt ? new Date(inst.lastLoginAt).toLocaleString('en-IN') : 'Never',
      papers: 0
    }));
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'DB Error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /papers (Backward-compatibility)
// ─────────────────────────────────────────────────────────────
app.get('/papers', async (req, res) => {
  try {
    const papers = await PaperModel.find({});
    const data = papers.map(p => ({
      examId: p.examId,
      paperCode: p.paperCode,
      examName: p.examName,
      subject: p.subject,
      uploadTime: new Date(p.uploadTime).toLocaleString('en-IN'),
      unlockTime: new Date(p.unlockTime).toLocaleString('en-IN'),
      status: p.isEmergencyLocked ? 'revoked' : (p.status || 'locked'),
      isEmergencyLocked: p.isEmergencyLocked || false,
      sha256Checksum: p.sha256Checksum || '',
      accessedBy: p.accessedBy && p.accessedBy.length ? `${p.accessedBy.length} Centers` : '—'
    }));
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'DB Error' });
  }
});

// ── 404 handler ───────────────────────────────────────────────
app.use((req, res) => {
  if (req.accepts('html')) {
    return res.sendFile(path.join(__dirname, '../frontend/login.html'));
  }
  res.status(404).json({ success: false, message: 'Route not found.' });
});

// ── Global error handler ──────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[Unhandled Error]', err);
  res.status(500).json({ success: false, message: 'Something went wrong.' });
});

// ── Start server ──────────────────────────────────────────────
const DEFAULT_PORT = process.env.PORT || 5000;

function startServer(port) {
  const server = app.listen(port, () => {
    console.log(`🚀 VaultO Secure Core Backend running on http://localhost:${port}`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      const nextPort = Number(port) + 1;
      console.warn(`⚠️ Port ${port} in use, automatically trying http://localhost:${nextPort}`);
      startServer(nextPort);
    } else {
      console.error('Server error:', err);
    }
  });

  return server;
}

const serverInstance = startServer(DEFAULT_PORT);

module.exports = { app, serverInstance };
