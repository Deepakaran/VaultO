const jwt = require('jsonwebtoken');

/**
 * Signs a JWT token with the given payload.
 * @param {object} payload - Data to encode (e.g. { id, role })
 * @returns {string} signed JWT
 */
const signToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
};

/**
 * Verifies and decodes a JWT token.
 * @param {string} token
 * @returns {object} decoded payload
 */
const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

module.exports = { signToken, verifyToken };
