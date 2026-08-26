const { verifyToken } = require('../utils/jwtHelper');

/**
 * Middleware to authenticate JWT and enforce admin role.
 */
const requireAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Authentication required. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied. Admin privileges required.' });
    }

    req.admin = decoded;
    next();
  } catch (err) {
    console.error('[requireAdmin middleware]', err.message);
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
};

/**
 * Middleware to authenticate JWT and enforce institute role.
 */
const requireInstitute = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Authentication required. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (decoded.role !== 'institute') {
      return res.status(403).json({ success: false, message: 'Access denied. Institute privileges required.' });
    }

    req.institute = decoded;
    next();
  } catch (err) {
    console.error('[requireInstitute middleware]', err.message);
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
};

/**
 * Middleware to authenticate JWT and enforce authority role (or allow admin/authority).
 */
const requireAuthority = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Authentication required. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (decoded.role !== 'authority' && decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied. Authority privileges required.' });
    }

    req.authority = decoded;
    next();
  } catch (err) {
    console.error('[requireAuthority middleware]', err.message);
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
};

module.exports = { requireAdmin, requireInstitute, requireAuthority };
