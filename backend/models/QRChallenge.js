const mongoose = require('mongoose');

const CHALLENGE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

const qrChallengeSchema = new mongoose.Schema({
  challengeId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  examId: {
    type: String,
    required: true,
    index: true,
  },
  instituteId: {
    type: String,
    required: true,
    index: true,
  },
  desktopNonce: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['PENDING', 'SCANNED', 'AUTHORIZED', 'USED', 'EXPIRED'],
    default: 'PENDING',
  },
  authorityId: {
    type: String,
    default: '',
  },
  authorityDeviceId: {
    type: String,
    default: '',
  },
  biometricVerified: {
    type: Boolean,
    default: false,
  },
  trustedTimeSynced: {
    type: Boolean,
    default: false,
  },
  authorizationToken: {
    type: String,
    default: '',
  },
  authorizedAt: {
    type: Date,
    default: null,
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + CHALLENGE_EXPIRY_MS),
    index: { expires: 0 },
  },
}, { timestamps: true });

module.exports = mongoose.model('QRChallenge', qrChallengeSchema);
module.exports.CHALLENGE_EXPIRY_MS = CHALLENGE_EXPIRY_MS;
