const mongoose = require('mongoose');

const OTP_EXPIRY_MS  = 5 * 60 * 1000; // 5 minutes
const MAX_ATTEMPTS   = 3;

const otpStoreSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    index: true,
  },
  // 'signup' | 'login' | 'reset'
  purpose: {
    type: String,
    required: true,
    enum: ['signup', 'login', 'reset'],
  },
  // bcrypt hash of the OTP — never store plain text
  otpHash: {
    type: String,
    required: true,
  },
  // Number of failed verification attempts so far
  attempts: {
    type: Number,
    default: 0,
    max: MAX_ATTEMPTS,
  },
  // TTL index — MongoDB auto-deletes this document when expiresAt is reached
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + OTP_EXPIRY_MS),
    index: { expires: 0 },
  },
});

module.exports = mongoose.model('OtpStore', otpStoreSchema);
module.exports.MAX_ATTEMPTS  = MAX_ATTEMPTS;
module.exports.OTP_EXPIRY_MS = OTP_EXPIRY_MS;
