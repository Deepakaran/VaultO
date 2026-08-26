const { randomInt } = require('crypto');

/**
 * Generates a cryptographically secure random 6-digit OTP string.
 * Uses Node's `crypto.randomInt` instead of Math.random for true randomness.
 * @returns {string} e.g. "083421"
 */
const generateOtp = () => {
  // randomInt(min, max) is inclusive of min, exclusive of max
  return randomInt(100000, 1000000).toString();
};

module.exports = generateOtp;
