const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');

const Admin              = require('../models/Admin');
const Institute          = require('../models/Institute');
const { sendOTP, verifyOTP } = require('../utils/otpService');

// ─────────────────────────────────────────────────────────────
// Helper: find verified account across both collections
// ─────────────────────────────────────────────────────────────
const findAccount = async (email) => {
  const admin = await Admin.findOne({ email, isVerified: true });
  if (admin) return { account: admin, role: 'admin' };

  const institute = await Institute.findOne({ email, isVerified: true });
  if (institute) return { account: institute, role: 'institute' };

  return { account: null, role: null };
};

// ─────────────────────────────────────────────────────────────
// POST /forgot-password
// Body: { email }
// Sends a password-reset OTP (always 200 to prevent email enumeration)
// ─────────────────────────────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, message: 'Email is required.' });

    const normalizedEmail = email.toLowerCase().trim();
    const GENERIC_MSG = 'If an account exists with this email, a reset OTP has been sent.';

    const { account } = await findAccount(normalizedEmail);

    // Always return 200 — prevents email enumeration
    if (!account)
      return res.status(200).json({ success: true, message: GENERIC_MSG });

    // Send reset OTP (console-simulated)
    await sendOTP(normalizedEmail, 'reset');

    return res.status(200).json({ success: true, message: GENERIC_MSG });
  } catch (err) {
    console.error('[POST /forgot-password]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────
// POST /reset-password
// Body: { email, otp, newPassword }
// Verifies reset OTP then updates the account password
// ─────────────────────────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword)
      return res.status(400).json({ success: false, message: 'Email, OTP, and new password are required.' });

    if (newPassword.length < 8)
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });

    const normalizedEmail = email.toLowerCase().trim();

    // 1. Verify OTP (attempt limiting + auto-delete on success/lockout)
    const otpResult = await verifyOTP(normalizedEmail, otp, 'reset');
    if (!otpResult.success)
      return res.status(401).json({
        success: false,
        message: otpResult.message,
        attemptsLeft: otpResult.attemptsLeft,
      });

    // 2. Find account
    const { account, role } = await findAccount(normalizedEmail);
    if (!account)
      return res.status(404).json({ success: false, message: 'Account not found.' });

    // 3. Hash and save new password
    const passwordHash = await bcrypt.hash(newPassword, 12);
    if (role === 'admin') {
      await Admin.findByIdAndUpdate(account._id, { password: passwordHash });
    } else {
      await Institute.findByIdAndUpdate(account._id, { password: passwordHash });
    }

    return res.status(200).json({ success: true, message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error('[POST /reset-password]', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

module.exports = router;

