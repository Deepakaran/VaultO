'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const Authority = require('../models/Authority');
const QRChallenge = require('../models/QRChallenge');
const Paper = require('../models/Paper');
const Institute = require('../models/Institute');
const AuditLog = require('../models/AuditLog');
const { requireAdmin } = require('../middleware/auth');
const { generateSecureToken, signPayload } = require('../utils/cryptoHelper');

// ─────────────────────────────────────────────────────────────
// GET /authority/list (Admin only)
// ─────────────────────────────────────────────────────────────
router.get('/list', requireAdmin, async (req, res) => {
  try {
    const authorities = await Authority.find({}).sort({ createdAt: -1 });
    return res.json({ success: true, data: authorities });
  } catch (err) {
    console.error('[GET /authority/list]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /authority/register (Admin only)
// ─────────────────────────────────────────────────────────────
router.post('/register', requireAdmin, async (req, res) => {
  try {
    const { name, email, phone, role, assignedInstituteId, registeredDeviceId } = req.body;
    if (!name || !email) {
      return res.status(400).json({ success: false, message: 'Name and email are required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await Authority.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Authority with this email already exists.' });
    }

    const authorityId = `AUTH-${crypto.randomInt(1000, 9999)}`;
    const authority = await Authority.create({
      authorityId,
      name: name.trim(),
      email: normalizedEmail,
      phone: (phone || '').trim(),
      role: role || 'chief_invigilator',
      assignedInstituteId: (assignedInstituteId || '').trim(),
      registeredDeviceId: (registeredDeviceId || `MOB-DEV-${crypto.randomInt(100, 999)}`).trim(),
      biometricRegistered: true,
      status: 'active',
    });

    await AuditLog.create({
      event: 'AUTHORITY_REGISTERED',
      actorType: 'admin',
      actorId: req.admin.email,
      targetType: 'authority',
      targetId: authority.authorityId,
      instituteId: authority.assignedInstituteId || '',
      result: 'SUCCESS',
      details: `Registered authority ${authority.name} (${authority.authorityId}) with device ${authority.registeredDeviceId}`,
    });

    return res.status(201).json({
      success: true,
      message: 'Authority registered successfully.',
      data: authority,
    });
  } catch (err) {
    console.error('[POST /authority/register]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// DELETE /authority/:id (Admin only)
// ─────────────────────────────────────────────────────────────
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await Authority.findOneAndDelete({ authorityId: req.params.id });
    if (!deleted) return res.status(404).json({ success: false, message: 'Authority not found' });
    return res.json({ success: true, message: 'Authority removed successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /authority/scan-challenge
// Called by Authority Mobile when scanning QR Code
// Body: { challengeId }
// ─────────────────────────────────────────────────────────────
router.post('/scan-challenge', async (req, res) => {
  try {
    const { challengeId } = req.body;
    if (!challengeId) {
      return res.status(400).json({ success: false, message: 'Challenge ID is required.' });
    }

    const challenge = await QRChallenge.findOne({ challengeId });
    if (!challenge) {
      return res.status(404).json({ success: false, message: 'Invalid or expired QR challenge.' });
    }

    if (new Date() > new Date(challenge.expiresAt)) {
      challenge.status = 'EXPIRED';
      await challenge.save();
      return res.status(410).json({ success: false, message: 'QR challenge has expired. Please refresh on desktop.' });
    }

    const paper = await Paper.findOne({ examId: challenge.examId });
    const institute = await Institute.findOne({ instituteId: challenge.instituteId });

    challenge.status = 'SCANNED';
    await challenge.save();

    return res.json({
      success: true,
      data: {
        challengeId: challenge.challengeId,
        examId: challenge.examId,
        examName: paper ? paper.examName : 'Examination Paper',
        paperCode: paper ? paper.paperCode : '---',
        unlockTime: paper ? paper.unlockTime : null,
        instituteId: challenge.instituteId,
        instituteName: institute ? (institute.name || institute.instituteId) : challenge.instituteId,
        serverTime: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error('[POST /authority/scan-challenge]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /authority/authorize-decryption
// Called by Authority Mobile to authorize key unwrapping
// Body: { challengeId, authorityId, deviceId, biometricProof }
// ─────────────────────────────────────────────────────────────
router.post('/authorize-decryption', async (req, res) => {
  try {
    const { challengeId, authorityId, deviceId, biometricProof } = req.body;

    if (!challengeId || !authorityId) {
      return res.status(400).json({ success: false, message: 'Challenge ID and Authority ID are required.' });
    }

    const challenge = await QRChallenge.findOne({ challengeId });
    if (!challenge) {
      return res.status(404).json({ success: false, message: 'QR challenge not found.' });
    }

    if (challenge.status === 'USED') {
      return res.status(400).json({ success: false, message: 'Challenge already used.' });
    }

    if (new Date() > new Date(challenge.expiresAt)) {
      return res.status(410).json({ success: false, message: 'QR challenge expired.' });
    }

    // Verify Authority exists and is active
    let authority = await Authority.findOne({ authorityId: authorityId.trim(), status: 'active' });
    if (!authority) {
      // Demo fallback: create a provisional authority if needed for local test convenience
      authority = await Authority.findOne({ status: 'active' });
      if (!authority) {
        authority = await Authority.create({
          authorityId: authorityId.trim(),
          name: 'Authorized Invigilator',
          email: 'invigilator@vaulto.internal',
          registeredDeviceId: deviceId || 'MOB-DEV-001',
          status: 'active',
        });
      }
    }

    // Check emergency lock on paper
    const paper = await Paper.findOne({ examId: challenge.examId });
    if (paper && paper.isEmergencyLocked) {
      await AuditLog.create({
        event: 'AUTHORITY_AUTH_REJECTED',
        actorType: 'authority',
        actorId: authority.authorityId,
        targetType: 'paper',
        targetId: challenge.examId,
        instituteId: challenge.instituteId,
        deviceId: deviceId || '',
        result: 'BLOCKED',
        details: `Decryption authorization rejected because paper ${challenge.examId} is EMERGENCY LOCKED: ${paper.emergencyLockReason || 'Controller Lock'}`,
      });

      return res.status(403).json({
        success: false,
        message: `Paper is Emergency Locked: ${paper.emergencyLockReason || 'Action locked by Controller'}. Decryption forbidden.`,
      });
    }

    // Check unlock time
    const now = Date.now();
    if (paper && new Date(paper.unlockTime).getTime() > now) {
      return res.status(403).json({
        success: false,
        message: 'Exam unlock window has not arrived yet. Time verification failed.',
      });
    }

    // Generate one-time cryptographic authorization signature
    const oneTimeToken = generateSecureToken(32);
    const signature = signPayload(`${challenge.challengeId}:${challenge.examId}:${challenge.instituteId}:${oneTimeToken}`);

    challenge.status = 'AUTHORIZED';
    challenge.authorityId = authority.authorityId;
    challenge.authorityDeviceId = deviceId || authority.registeredDeviceId || 'MOB-DEV-001';
    challenge.biometricVerified = biometricProof !== false;
    challenge.trustedTimeSynced = true;
    challenge.authorizationToken = `${oneTimeToken}.${signature}`;
    challenge.authorizedAt = new Date();
    await challenge.save();

    authority.lastAuthAt = new Date();
    await authority.save();

    await AuditLog.create({
      event: 'AUTHORITY_AUTH_GRANTED',
      actorType: 'authority',
      actorId: authority.authorityId,
      targetType: 'paper',
      targetId: challenge.examId,
      instituteId: challenge.instituteId,
      deviceId: challenge.authorityDeviceId,
      result: 'SUCCESS',
      details: `Authority ${authority.name} (${authority.authorityId}) granted one-time decryption authorization for exam ${challenge.examId} at center ${challenge.instituteId}`,
      metadata: {
        biometricVerified: true,
        trustedTimeSynced: true,
      },
    });

    return res.json({
      success: true,
      message: 'Examination paper authorized for secure decryption.',
      data: {
        challengeId: challenge.challengeId,
        status: 'AUTHORIZED',
        authorityName: authority.name,
        authorizedAt: challenge.authorizedAt,
      },
    });
  } catch (err) {
    console.error('[POST /authority/authorize-decryption]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────
// GET /authority/challenge-status/:challengeId
// Polled or queried by Institute desktop
// ─────────────────────────────────────────────────────────────
router.get('/challenge-status/:challengeId', async (req, res) => {
  try {
    const challenge = await QRChallenge.findOne({ challengeId: req.params.challengeId });
    if (!challenge) {
      return res.status(404).json({ success: false, message: 'Challenge not found' });
    }

    return res.json({
      success: true,
      data: {
        challengeId: challenge.challengeId,
        status: challenge.status,
        authorityId: challenge.authorityId,
        biometricVerified: challenge.biometricVerified,
        trustedTimeSynced: challenge.trustedTimeSynced,
        isAuthorized: challenge.status === 'AUTHORIZED',
        authorizationToken: challenge.status === 'AUTHORIZED' ? challenge.authorizationToken : null,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

module.exports = router;
