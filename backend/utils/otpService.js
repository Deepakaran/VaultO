/**
 * otpService.js
 * ─────────────────────────────────────────────────────────────────────
 * Core OTP service for VaultO.
 *
 * sendOTP(email, purpose)        – generate, store (hashed), and email an OTP
 * verifyOTP(email, otp, purpose) – verify OTP with attempt limiting
 *
 * Rules enforced:
 *   • 6-digit numeric OTP (crypto.randomInt)
 *   • 5-minute expiry (enforced both by MongoDB TTL and in code)
 *   • Max 3 failed attempts → OTP is invalidated (deleted)
 *   • Auto-deleted from DB after successful verification
 *   • Real email delivery via Gmail SMTP (nodemailer) + console log
 * ─────────────────────────────────────────────────────────────────────
 */

'use strict';

const bcrypt          = require('bcryptjs');
const OtpStore        = require('../models/OtpStore');
const generateOtp     = require('./generateOtp');
const { sendOtpEmail } = require('../services/mailService');

const { MAX_ATTEMPTS, OTP_EXPIRY_MS } = OtpStore;
const BCRYPT_ROUNDS = 10; // lighter than password hashing – OTPs are short-lived

// ─────────────────────────────────────────────────────────────────────
// sendOTP(email, purpose)
// ─────────────────────────────────────────────────────────────────────
/**
 * Generates a 6-digit OTP, stores it (hashed) in the DB, and sends it
 * to the recipient's email via Gmail SMTP. The OTP is also logged to
 * the console for easy local testing.
 *
 * Any previous OTP for the same email+purpose is removed first so only
 * one valid OTP exists at a time.
 *
 * @param {string} email   - Recipient email address
 * @param {string} purpose - 'signup' | 'login' | 'reset'
 * @returns {Promise<{ success: boolean, message: string }>}
 */
async function sendOTP(email, purpose = 'login') {
  if (!email || !purpose) {
    return { success: false, message: 'Email and purpose are required.' };
  }

  if (!['signup', 'login', 'reset'].includes(purpose)) {
    return { success: false, message: `Invalid purpose "${purpose}". Must be signup | login | reset.` };
  }

  const normalizedEmail = email.toLowerCase().trim();

  // 1. Generate plain-text OTP (cryptographically secure)
  const otp = generateOtp();

  // 2. Hash it before storing (never persist plain-text OTPs)
  const otpHash = await bcrypt.hash(otp, BCRYPT_ROUNDS);

  // 3. Remove any existing OTP for this email + purpose (idempotent re-send)
  await OtpStore.deleteMany({ email: normalizedEmail, purpose });

  // 4. Persist new OTP record with TTL-backed expiry
  await OtpStore.create({
    email:     normalizedEmail,
    purpose,
    otpHash,
    attempts:  0,
    expiresAt: new Date(Date.now() + OTP_EXPIRY_MS),
  });

  // 5. Send real email (also logs OTP to console for development)
  const mailResult = await sendOtpEmail(normalizedEmail, otp, purpose);
  if (!mailResult.success) {
    return { success: false, message: mailResult.message };
  }

  return {
    success: true,
    message: `OTP sent to ${normalizedEmail}. It expires in 5 minutes.`,
  };
}


// ─────────────────────────────────────────────────────────────────────
// verifyOTP(email, otp, purpose)
// ─────────────────────────────────────────────────────────────────────
/**
 * Verifies an OTP submitted by the user.
 *
 * Outcome table:
 *  ┌───────────────────────────────┬──────────────────────────────────┐
 *  │ Scenario                      │ Result                           │
 *  ├───────────────────────────────┼──────────────────────────────────┤
 *  │ No record found               │ expired / not found error        │
 *  │ expiresAt passed (double-chk) │ expired error (+ delete record)  │
 *  │ attempts >= MAX_ATTEMPTS      │ locked error (+ delete record)   │
 *  │ OTP mismatch                  │ invalid OTP, increments attempts │
 *  │ OTP matches                   │ success + auto-deletes record    │
 *  └───────────────────────────────┴──────────────────────────────────┘
 *
 * @param {string} email   - User's email
 * @param {string} otp     - Plain-text OTP submitted by user
 * @param {string} purpose - 'signup' | 'login' | 'reset'
 * @returns {Promise<{ success: boolean, message: string, attemptsLeft?: number }>}
 */
async function verifyOTP(email, otp, purpose = 'login') {
  if (!email || !otp || !purpose) {
    return { success: false, message: 'Email, OTP, and purpose are required.' };
  }

  const normalizedEmail = email.toLowerCase().trim();

  // 1. Find the OTP record
  const record = await OtpStore.findOne({ email: normalizedEmail, purpose });

  if (!record) {
    return {
      success: false,
      message: 'OTP not found or has expired. Please request a new one.',
    };
  }

  // 2. Manual expiry double-check (belt + suspenders alongside TTL)
  if (new Date() > record.expiresAt) {
    await OtpStore.deleteOne({ _id: record._id });
    return {
      success: false,
      message: 'OTP has expired. Please request a new one.',
    };
  }

  // 3. Attempts guard — lock out if already exhausted
  if (record.attempts >= MAX_ATTEMPTS) {
    await OtpStore.deleteOne({ _id: record._id });
    return {
      success: false,
      message: `Too many failed attempts. OTP invalidated. Please request a new one.`,
    };
  }

  // 4. Compare OTP against stored hash
  const isMatch = await bcrypt.compare(otp, record.otpHash);

  if (!isMatch) {
    // Increment attempt counter
    record.attempts += 1;
    await record.save();

    const attemptsLeft = MAX_ATTEMPTS - record.attempts;

    // Auto-delete if this was the last allowed attempt
    if (attemptsLeft === 0) {
      await OtpStore.deleteOne({ _id: record._id });
      return {
        success: false,
        message: 'Invalid OTP. Maximum attempts reached. OTP invalidated.',
        attemptsLeft: 0,
      };
    }

    return {
      success: false,
      message: `Invalid OTP. ${attemptsLeft} attempt${attemptsLeft === 1 ? '' : 's'} remaining.`,
      attemptsLeft,
    };
  }

  // 5. ✅ OTP is correct — auto-delete (single use)
  await OtpStore.deleteOne({ _id: record._id });

  return {
    success: true,
    message: 'OTP verified successfully.',
  };
}

module.exports = { sendOTP, verifyOTP };
