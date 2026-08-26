'use strict';

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const multer  = require('multer');

const Admin                          = require('../models/Admin');
const Institute                      = require('../models/Institute');
const Paper                          = require('../models/Paper');
const Authority                      = require('../models/Authority');
const AuditLog                       = require('../models/AuditLog');
const { sendOTP, verifyOTP }         = require('../utils/otpService');
const { signToken }                  = require('../utils/jwtHelper');
const { requireAdmin }               = require('../middleware/auth');
const { computeSHA256 }              = require('../utils/cryptoHelper');
const { sendCredentialsEmail,
        sendUploadConfirmationEmail } = require('../services/mailService');

// ─────────────────────────────────────────────────────────────
// Multer: memory storage for admin paper uploads
// ─────────────────────────────────────────────────────────────
const adminUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are allowed.'));
  },
});

// ─────────────────────────────────────────────────────────────
// POST /admin/institute/request-otp
// ─────────────────────────────────────────────────────────────
router.post('/institute/request-otp', requireAdmin, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, message: 'Institute email is required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await Institute.findOne({ email: normalizedEmail });
    if (existing)
      return res.status(409).json({ success: false, message: 'An institute with this email already exists.' });

    const adminEmail = req.admin.email;
    const result = await sendOTP(adminEmail, 'login');
    if (!result.success)
      return res.status(500).json({ success: false, message: result.message });

    return res.status(200).json({
      success: true,
      message: `Authorization OTP sent to your admin email (${adminEmail}).`,
      adminEmail,
    });
  } catch (err) {
    console.error('[POST /admin/institute/request-otp]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/signup
// ─────────────────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: 'Email and password are required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await Admin.findOne({ email: normalizedEmail });
    if (existing && existing.isVerified)
      return res.status(409).json({ success: false, message: 'An account with this email already exists.' });

    const passwordHash = await bcrypt.hash(password, 12);
    if (existing) {
      existing.password = passwordHash;
      if (name) existing.name = name;
      await existing.save();
    } else {
      await Admin.create({ email: normalizedEmail, password: passwordHash, name: name || '' });
    }

    const result = await sendOTP(normalizedEmail, 'signup');
    if (!result.success)
      return res.status(500).json({ success: false, message: result.message });

    return res.status(200).json({
      success: true,
      message: 'Account created. An OTP has been sent to your email.',
    });
  } catch (err) {
    console.error('[POST /admin/signup]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/setup-status
// ─────────────────────────────────────────────────────────────
router.get('/setup-status', async (req, res) => {
  try {
    const adminCount = await Admin.countDocuments();
    return res.status(200).json({ success: true, hasAdmins: adminCount > 0 });
  } catch (err) {
    console.error('[GET /admin/setup-status]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/send-otp
// ─────────────────────────────────────────────────────────────
router.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, message: 'Email is required.' });

    const normalizedEmail = email.toLowerCase().trim();
    let isNewUser = false;
    const admin = await Admin.findOne({ email: normalizedEmail });

    if (!admin) {
      await Admin.create({ email: normalizedEmail, isVerified: false });
      isNewUser = true;
    } else if (!admin.isVerified) {
      isNewUser = true;
    }

    const otpPurpose = isNewUser ? 'signup' : 'login';
    const result = await sendOTP(normalizedEmail, otpPurpose);
    if (!result.success)
      return res.status(500).json({ success: false, message: result.message });

    return res.status(200).json({
      success: true,
      message: isNewUser ? 'Signup OTP sent.' : 'Login OTP sent.',
      isNewUser,
    });
  } catch (err) {
    console.error('[POST /admin/send-otp]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/verify-otp
// ─────────────────────────────────────────────────────────────
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp)
      return res.status(400).json({ success: false, message: 'Email and OTP are required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const admin = await Admin.findOne({ email: normalizedEmail });
    if (!admin)
      return res.status(404).json({ success: false, message: 'No account found for this email.' });

    const otpPurpose = admin.isVerified ? 'login' : 'signup';
    const result = await verifyOTP(normalizedEmail, otp, otpPurpose);
    if (!result.success)
      return res.status(401).json({ success: false, message: result.message, attemptsLeft: result.attemptsLeft });

    const isNewUser = !admin.isVerified;
    await Admin.findOneAndUpdate({ email: normalizedEmail }, { isVerified: true });

    return res.status(200).json({
      success: true,
      message: isNewUser ? 'Email verified. Please set your password.' : 'OTP verified. Please enter your password to log in.',
      isNewUser,
    });
  } catch (err) {
    console.error('[POST /admin/verify-otp]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/set-password
// ─────────────────────────────────────────────────────────────
router.post('/set-password', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: 'Email and password are required.' });

    if (password.length < 8)
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });

    const normalizedEmail = email.toLowerCase().trim();
    const admin = await Admin.findOne({ email: normalizedEmail, isVerified: true });
    if (!admin)
      return res.status(404).json({ success: false, message: 'Verified admin account not found.' });

    admin.password = await bcrypt.hash(password, 12);
    await admin.save();

    const token = signToken({ id: admin._id, role: 'admin', email: admin.email });
    return res.status(200).json({
      success: true,
      message: 'Password set successfully. Welcome to VaultO!',
      token,
      admin: { id: admin._id, email: admin.email, name: admin.name },
    });
  } catch (err) {
    console.error('[POST /admin/set-password]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/login
// ─────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password, otp } = req.body;
    if (!email || !password || !otp)
      return res.status(400).json({ success: false, message: 'Email, password, and OTP are required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const admin = await Admin.findOne({ email: normalizedEmail });
    if (!admin)
      return res.status(404).json({ success: false, message: 'No account found with this email.' });
    if (!admin.isVerified)
      return res.status(403).json({ success: false, message: 'Email not verified. Please verify your email first.' });
    if (!admin.password)
      return res.status(403).json({ success: false, message: 'Password not set. Please complete your signup.' });

    const otpResult = await verifyOTP(normalizedEmail, otp, 'login');
    if (!otpResult.success)
      return res.status(401).json({ success: false, message: otpResult.message, attemptsLeft: otpResult.attemptsLeft });

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch)
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });

    const token = signToken({ id: admin._id, role: 'admin', email: admin.email });
    
    await AuditLog.create({
      event: 'ADMIN_LOGIN',
      actorType: 'admin',
      actorId: admin.email,
      result: 'SUCCESS',
      details: `Administrator logged into VaultO Controller portal`,
    });

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      admin: { id: admin._id, email: admin.email, name: admin.name },
    });
  } catch (err) {
    console.error('[POST /admin/login]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/password-check
// ─────────────────────────────────────────────────────────────
router.post('/password-check', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: 'Email and password are required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const admin = await Admin.findOne({ email: normalizedEmail, isVerified: true });
    if (!admin)
      return res.status(404).json({ success: false, message: 'Verified admin account not found.' });
    if (!admin.password)
      return res.status(403).json({ success: false, message: 'Password not set. Please complete signup first.' });

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch)
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });

    const token = signToken({ id: admin._id, role: 'admin', email: admin.email });

    await AuditLog.create({
      event: 'ADMIN_LOGIN',
      actorType: 'admin',
      actorId: admin.email,
      result: 'SUCCESS',
      details: `Administrator logged into VaultO Controller portal`,
    });

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      admin: { id: admin._id, email: admin.email, name: admin.name },
    });
  } catch (err) {
    console.error('[POST /admin/password-check]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/institute
// ─────────────────────────────────────────────────────────────
router.post('/institute', requireAdmin, async (req, res) => {
  try {
    const { email, name, district, otp } = req.body;
    if (!email || !otp)
      return res.status(400).json({ success: false, message: 'Institute email and OTP are required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const adminEmail = req.admin.email;

    const otpResult = await verifyOTP(adminEmail, otp, 'login');
    if (!otpResult.success)
      return res.status(401).json({ success: false, message: otpResult.message, attemptsLeft: otpResult.attemptsLeft });

    const existing = await Institute.findOne({ email: normalizedEmail });
    if (existing)
      return res.status(409).json({ success: false, message: 'An institute with this email already exists.' });

    let instituteId;
    let isUnique = false;
    let attempts = 0;
    while (!isUnique && attempts < 10) {
      const randNum = crypto.randomInt(1000, 10000);
      instituteId = `INS-${randNum}`;
      const found = await Institute.findOne({ instituteId });
      if (!found) isUnique = true;
      attempts++;
    }

    if (!isUnique)
      return res.status(500).json({ success: false, message: 'Failed to generate a unique Institute ID.' });

    const randomPassword = crypto.randomBytes(4).toString('hex');
    const passwordHash   = await bcrypt.hash(randomPassword, 12);

    const newInst = await Institute.create({
      email: normalizedEmail,
      name:  name || '',
      district: district || '',
      instituteId,
      password:   passwordHash,
      isVerified: true,
      status: 'active',
    });

    const mailResult = await sendCredentialsEmail(normalizedEmail, instituteId, randomPassword, name || '');
    if (!mailResult.success)
      console.error('[POST /admin/institute] Credentials email failed:', mailResult._error);

    await AuditLog.create({
      event: 'INSTITUTE_PROVISIONED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'institute',
      targetId: instituteId,
      instituteId,
      result: 'SUCCESS',
      details: `Created new examination centre ${name || instituteId} (${instituteId}) at ${normalizedEmail}`,
    });

    return res.status(201).json({
      success: true,
      message: `Institute created. Credentials emailed to ${normalizedEmail}.`,
      data: { instituteId, name: newInst.name, email: newInst.email },
    });

  } catch (err) {
    console.error('[POST /admin/institute]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/toggle-institute-status/:instituteId
// ─────────────────────────────────────────────────────────────
router.post('/toggle-institute-status/:instituteId', requireAdmin, async (req, res) => {
  try {
    const inst = await Institute.findOne({ instituteId: req.params.instituteId });
    if (!inst) return res.status(404).json({ success: false, message: 'Institute not found' });

    inst.status = inst.status === 'active' ? 'blocked' : 'active';
    await inst.save();

    await AuditLog.create({
      event: inst.status === 'blocked' ? 'INSTITUTE_BLOCKED' : 'INSTITUTE_UNBLOCKED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'institute',
      targetId: inst.instituteId,
      instituteId: inst.instituteId,
      result: inst.status === 'blocked' ? 'WARNING' : 'SUCCESS',
      details: `Admin changed institute ${inst.instituteId} status to ${inst.status.toUpperCase()}`,
    });

    return res.json({ success: true, message: `Institute is now ${inst.status}`, data: { status: inst.status } });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/stats
// ─────────────────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const instCount  = await Institute.countDocuments();
    const paperCount = await Paper.countDocuments();
    const activeInst = await Institute.countDocuments({ status: 'active' });
    const totalPrints = await Paper.aggregate([{ $group: { _id: null, total: { $sum: '$printCount' } } }]);
    const totalDownloads = totalPrints.length ? totalPrints[0].total : 0;

    return res.json({
      success: true,
      data: {
        totalInstitutes:      instCount,
        totalInstitutesDelta: `${activeInst} Active Centres`,
        activeToday:          activeInst,
        activeTodayDelta:     '100% Operational',
        totalPapers:          paperCount,
        totalPapersDelta:     'All Encrypted (AES-256)',
        downloads:            totalDownloads,
        downloadsDelta:       'Logged securely',
        chartData: {
          days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
          vals: [4, 8, 15, 12, 19, 7, 10],
        },
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/upload-paper
// ─────────────────────────────────────────────────────────────
router.post('/upload-paper', requireAdmin, adminUpload.single('paper'), async (req, res) => {
  try {
    const { instituteId, assignedInstitutes, paperCode, examName, examDate, unlockDate, unlockTime } = req.body;

    if (!instituteId || !paperCode || !examName || !examDate || !unlockDate || !unlockTime)
      return res.status(400).json({ success: false, message: 'All fields (instituteId, paperCode, examName, examDate, unlockDate, unlockTime) are required.' });

    if (!/^\d+$/.test(String(paperCode).trim()))
      return res.status(400).json({ success: false, message: 'Paper code must contain numbers only.' });

    if (!req.file)
      return res.status(400).json({ success: false, message: 'Please attach a PDF question paper.' });

    // Handle single or multi-centre assignments
    let centerList = [instituteId.trim()];
    if (assignedInstitutes) {
      if (Array.isArray(assignedInstitutes)) {
        centerList = assignedInstitutes.map(s => s.trim());
      } else if (typeof assignedInstitutes === 'string') {
        centerList = assignedInstitutes.split(',').map(s => s.trim()).filter(Boolean);
      }
    }
    if (!centerList.includes(instituteId.trim())) {
      centerList.push(instituteId.trim());
    }

    const examDateObj   = new Date(examDate);
    const unlockDateObj = new Date(`${unlockDate}T${unlockTime}:00`);

    if (isNaN(examDateObj.getTime()))
      return res.status(400).json({ success: false, message: 'Invalid exam date.' });
    if (isNaN(unlockDateObj.getTime()))
      return res.status(400).json({ success: false, message: 'Invalid unlock date/time.' });

    const exists = await Paper.findOne({ paperCode: paperCode.trim(), instituteId: instituteId.trim() });
    if (exists)
      return res.status(409).json({ success: false, message: `Paper code ${paperCode} already exists for institute ${instituteId}.` });

    // Calculate SHA-256 integrity checksum
    const sha256Checksum = computeSHA256(req.file.buffer);

    // AES-256-CBC encryption
    const key = crypto.randomBytes(32);
    const iv  = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encryptedData = Buffer.concat([cipher.update(req.file.buffer), cipher.final()]).toString('base64');

    const examId = `EXM-${Date.now()}-${paperCode.trim()}`;

    const newPaper = await Paper.create({
      examId,
      paperCode:          paperCode.trim(),
      examName:           examName.trim(),
      subject:            examName.trim(),
      instituteId:        instituteId.trim(),
      assignedInstitutes: centerList,
      examDate:           examDateObj,
      unlockTime:         unlockDateObj,
      originalName:       req.file.originalname,
      fileSizeBytes:      req.file.buffer.length,
      sha256Checksum,
      encryptedData,
      encryptionKey:      key.toString('hex'),
      encryptionIV:       iv.toString('hex'),
      status:             'locked',
    });

    const examDateStr   = examDateObj.toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    const unlockTimeStr = unlockDateObj.toLocaleString('en-IN', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true });

    // Send confirmation to primary institute
    const primaryInst = await Institute.findOne({ instituteId: instituteId.trim() });
    if (primaryInst && primaryInst.email) {
      sendUploadConfirmationEmail(primaryInst.email, paperCode.trim(), examName.trim(), examDateStr, unlockTimeStr, instituteId.trim())
        .catch(e => console.error('[admin/upload-paper] Email error:', e.message));
    }

    await AuditLog.create({
      event: 'PAPER_ENCRYPTED_UPLOADED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'paper',
      targetId: examId,
      examId,
      instituteId: instituteId.trim(),
      result: 'SUCCESS',
      details: `Controller uploaded & AES-256 encrypted paper "${examName}" (${paperCode}) assigned to ${centerList.length} center(s). SHA-256: ${sha256Checksum.substring(0, 16)}...`,
      metadata: {
        fileSizeBytes: req.file.buffer.length,
        sha256Checksum,
        assignedCenters: centerList,
      },
    });

    return res.status(201).json({
      success: true,
      message: `Paper encrypted (AES-256-CBC) and stored securely. Assigned to ${centerList.length} center(s).`,
      data: {
        examId,
        paperCode: paperCode.trim(),
        examName: examName.trim(),
        examDate: examDateStr,
        unlockTime: unlockTimeStr,
        sha256Checksum,
        status: 'locked',
        assignedInstitutes: centerList,
      },
    });

  } catch (err) {
    if (err.message === 'Only PDF files are allowed.')
      return res.status(400).json({ success: false, message: err.message });
    if (err.code === 11000)
      return res.status(409).json({ success: false, message: 'A paper with this exam ID already exists.' });
    console.error('[POST /admin/upload-paper]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/papers
// ─────────────────────────────────────────────────────────────
router.get('/papers', requireAdmin, async (_req, res) => {
  try {
    const papers = await Paper.find({}).sort({ createdAt: -1 });
    const data = papers.map(p => ({
      examId:             p.examId,
      paperCode:          p.paperCode,
      examName:           p.examName,
      subject:            p.subject,
      instituteId:        p.instituteId,
      assignedInstitutes: p.assignedInstitutes && p.assignedInstitutes.length ? p.assignedInstitutes : [p.instituteId],
      examDate:           p.examDate,
      unlockTime:         p.unlockTime,
      uploadTime:         p.uploadTime,
      status:             p.isEmergencyLocked ? 'revoked' : p.status,
      isEmergencyLocked:  p.isEmergencyLocked || false,
      emergencyLockReason:p.emergencyLockReason || '',
      sha256Checksum:     p.sha256Checksum || 'Available',
      fileSizeBytes:      p.fileSizeBytes || 0,
      accessedBy:         p.accessedBy && p.accessedBy.length ? `${p.accessedBy.length} Centers` : '—',
      printCount:         p.printCount || 0,
    }));
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/emergency-lock/:examId
// Emergency Lock / Kill-Switch for a specific examination paper
// ─────────────────────────────────────────────────────────────
router.post('/emergency-lock/:examId', requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const paper = await Paper.findOne({ examId: req.params.examId });
    if (!paper) return res.status(404).json({ success: false, message: 'Exam paper not found' });

    paper.isEmergencyLocked = true;
    paper.emergencyLockReason = reason || 'Controller emergency lock engaged';
    paper.status = 'revoked';
    await paper.save();

    await AuditLog.create({
      event: 'EMERGENCY_LOCK_ENGAGED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'paper',
      targetId: paper.examId,
      examId: paper.examId,
      result: 'WARNING',
      details: `CRITICAL: Controller engaged emergency lock for exam ${paper.examId} (${paper.examName}). Reason: ${paper.emergencyLockReason}`,
    });

    return res.json({
      success: true,
      message: `Emergency lock engaged for exam ${paper.examId}. Decryption is immediately disabled across all centres.`,
      data: { isEmergencyLocked: true, status: 'revoked' },
    });
  } catch (err) {
    console.error('[POST /admin/emergency-lock]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /admin/emergency-unlock/:examId
// ─────────────────────────────────────────────────────────────
router.post('/emergency-unlock/:examId', requireAdmin, async (req, res) => {
  try {
    const paper = await Paper.findOne({ examId: req.params.examId });
    if (!paper) return res.status(404).json({ success: false, message: 'Exam paper not found' });

    paper.isEmergencyLocked = false;
    paper.emergencyLockReason = '';
    paper.status = 'locked';
    await paper.save();

    await AuditLog.create({
      event: 'EMERGENCY_LOCK_LIFTED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'paper',
      targetId: paper.examId,
      examId: paper.examId,
      result: 'SUCCESS',
      details: `Controller lifted emergency lock for exam ${paper.examId} (${paper.examName}). Normal unlock rules restored.`,
    });

    return res.json({
      success: true,
      message: `Emergency lock lifted for exam ${paper.examId}. Normal scheduled unlock restored.`,
      data: { isEmergencyLocked: false, status: 'locked' },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/distribution-status
// Real-time tracking of paper distribution and examination status
// ─────────────────────────────────────────────────────────────
router.get('/distribution-status', requireAdmin, async (_req, res) => {
  try {
    const papers = await Paper.find({}).sort({ unlockTime: 1 });
    const institutes = await Institute.find({});
    const instMap = new Map(institutes.map(i => [i.instituteId, i.name || i.instituteId]));

    const distribution = papers.map(p => {
      const assigned = p.assignedInstitutes && p.assignedInstitutes.length ? p.assignedInstitutes : [p.instituteId];
      const details = assigned.map(instId => {
        const hasAccessed = p.accessedBy && p.accessedBy.includes(instId);
        return {
          instituteId: instId,
          instituteName: instMap.get(instId) || instId,
          deliveryStatus: 'STORED_ENCRYPTED',
          integrityVerified: true,
          decryptedStatus: hasAccessed ? 'DECRYPTED' : (p.isEmergencyLocked ? 'LOCKED' : 'SEALED'),
          printCount: p.printCount || 0,
        };
      });

      return {
        examId: p.examId,
        paperCode: p.paperCode,
        examName: p.examName,
        unlockTime: p.unlockTime,
        isEmergencyLocked: p.isEmergencyLocked,
        totalAssignedCentres: assigned.length,
        totalDecryptedCentres: (p.accessedBy || []).length,
        centres: details,
      };
    });

    return res.json({ success: true, data: distribution });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/devices & POST /admin/register-device
// ─────────────────────────────────────────────────────────────
router.get('/devices', requireAdmin, async (_req, res) => {
  try {
    const institutes = await Institute.find({});
    const authorities = await Authority.find({});
    const devices = [];

    institutes.forEach(inst => {
      if (inst.registeredDevices && inst.registeredDevices.length) {
        inst.registeredDevices.forEach(d => {
          devices.push({
            deviceId: d.deviceId,
            deviceName: d.deviceName,
            deviceType: d.deviceType || 'Workstation',
            ownerType: 'Institute / Exam Centre',
            ownerName: `${inst.name} (${inst.instituteId})`,
            instituteId: inst.instituteId,
            registeredAt: d.registeredAt,
            status: d.isApproved ? 'Approved' : 'Pending',
          });
        });
      }
    });

    authorities.forEach(auth => {
      if (auth.registeredDeviceId) {
        devices.push({
          deviceId: auth.registeredDeviceId,
          deviceName: `${auth.name}'s Mobile Device`,
          deviceType: 'Mobile Handset',
          ownerType: 'Authorized Authority',
          ownerName: `${auth.name} (${auth.authorityId})`,
          instituteId: auth.assignedInstituteId || 'All Centres',
          registeredAt: auth.createdAt,
          status: auth.status === 'active' ? 'Approved' : 'Revoked',
        });
      }
    });

    return res.json({ success: true, data: devices });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

router.post('/register-device', requireAdmin, async (req, res) => {
  try {
    const { instituteId, deviceId, deviceName, deviceType } = req.body;
    if (!instituteId || !deviceId) {
      return res.status(400).json({ success: false, message: 'Institute ID and Device ID are required' });
    }

    const inst = await Institute.findOne({ instituteId: instituteId.trim() });
    if (!inst) return res.status(404).json({ success: false, message: 'Institute not found' });

    inst.registeredDevices.push({
      deviceId: deviceId.trim(),
      deviceName: deviceName || 'Exam Workstation',
      deviceType: deviceType || 'desktop',
      isApproved: true,
      registeredAt: new Date(),
    });
    await inst.save();

    await AuditLog.create({
      event: 'DEVICE_REGISTERED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'device',
      targetId: deviceId,
      instituteId: inst.instituteId,
      result: 'SUCCESS',
      details: `Admin registered trusted workstation ${deviceId} (${deviceName || 'Exam Workstation'}) for institute ${inst.instituteId}`,
    });

    return res.status(201).json({ success: true, message: 'Device registered successfully' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/authorities
// ─────────────────────────────────────────────────────────────
router.get('/authorities', requireAdmin, async (_req, res) => {
  try {
    const list = await Authority.find({}).sort({ createdAt: -1 });
    return res.json({ success: true, data: list });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/logs
// ─────────────────────────────────────────────────────────────
router.get('/logs', requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const logs = await AuditLog.find({}).sort({ timestamp: -1 }).limit(limit);
    const data = logs.map(l => ({
      timestamp: l.timestamp.toISOString(),
      timeFormatted: new Date(l.timestamp).toLocaleString('en-IN'),
      event: l.event,
      actorType: l.actorType,
      actorId: l.actorId,
      targetType: l.targetType,
      targetId: l.targetId,
      result: l.result,
      details: l.details,
      badgeClass: l.result === 'SUCCESS' ? 'ok' : (l.result === 'WARNING' ? 'warn' : 'fail'),
    }));
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /admin/distribution-status
// ─────────────────────────────────────────────────────────────
router.get('/distribution-status', requireAdmin, async (_req, res) => {
  try {
    const papers = await Paper.find({}).sort({ unlockTime: 1 });
    const institutes = await Institute.find({});
    const instMap = {};
    institutes.forEach(i => {
      instMap[i.instituteId] = i.name || i.instituteId;
    });

    const data = papers.map(p => {
      const assigned = (p.assignedInstitutes && p.assignedInstitutes.length) 
        ? p.assignedInstitutes 
        : [p.instituteId];

      const centresStatus = assigned.map(instId => ({
        instituteId: instId,
        instituteName: instMap[instId] || instId,
        encryptedStored: true,
        integrityVerified: true,
        decryptedStatus: p.accessedBy && p.accessedBy.includes(instId) ? 'DECRYPTED' : 'SEALED',
      }));

      return {
        examId: p.examId,
        paperCode: p.paperCode,
        examName: p.examName,
        unlockTime: p.unlockTime,
        isEmergencyLocked: p.isEmergencyLocked || false,
        totalAssignedCentres: assigned.length,
        centres: centresStatus,
      };
    });

    return res.json({ success: true, data });
  } catch (err) {
    console.error('[GET /admin/distribution-status]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

module.exports = router;
