const crypto = require('crypto');

/**
 * Compute SHA-256 checksum of a buffer or string
 */
function computeSHA256(data) {
  const hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

/**
 * Generate a cryptographically secure random token (hex)
 */
function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Generate an HMAC-SHA256 signature for verification tokens
 */
function signPayload(payloadString, secret = process.env.JWT_SECRET || 'vaulto_secret_fallback') {
  return crypto.createHmac('sha256', secret).update(payloadString).digest('hex');
}

/**
 * Verify an HMAC-SHA256 signature
 */
function verifyPayloadSignature(payloadString, signature, secret = process.env.JWT_SECRET || 'vaulto_secret_fallback') {
  const expected = signPayload(payloadString, secret);
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'));
}

module.exports = {
  computeSHA256,
  generateSecureToken,
  signPayload,
  verifyPayloadSignature,
};
