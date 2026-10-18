const rateLimit = require('express-rate-limit');

/**
 * Helper function to check if a request should bypass rate limiting.
 * @param {import('express').Request} req
 * @returns {boolean}
 */
const shouldBypass = (req) => {
  // 1. Bypass during local development if explicitly enabled in .env
  if (process.env.NODE_ENV === 'development' && process.env.BYPASS_RATE_LIMIT === 'true') {
    return true;
  }

  // 2. Secret Header Bypass (useful for testing, Postman, or emergency admin logins)
  const bypassHeader = req.headers['x-bypass-ratelimit'];
  if (process.env.RATE_LIMIT_BYPASS_KEY && bypassHeader === process.env.RATE_LIMIT_BYPASS_KEY) {
    return true;
  }

  // 3. Optional: Whitelist local loopback addresses in development mode
  const clientIp = req.ip || req.connection?.remoteAddress;
  const localIps = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
  if (process.env.NODE_ENV === 'development' && localIps.includes(clientIp)) {
    return true;
  }

  return false;
};

// Login Rate Limiter (Strict, for authentication endpoints)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    status: 429,
    error: 'Too many failed login attempts from this IP. Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Only count FAILED login attempts (HTTP 4xx/5xx). Successful logins (2xx) won't increment the counter.
  skipSuccessfulRequests: true,
  // Dynamic bypass execution
  skip: (req, res) => shouldBypass(req)
});

// General API Rate Limiter (Lenient, for standard routes)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // 200 requests per window
  message: {
    status: 429,
    error: 'Too many requests generated from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req, res) => shouldBypass(req)
});

module.exports = { loginLimiter, apiLimiter };