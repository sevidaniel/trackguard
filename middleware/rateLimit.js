const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Ibinalik sa 5 failed/repeated attempts
  message: 'Too many failed login attempts from this IP. Please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
  // Tinitiyak na bawat POST attempt sa /login ay mabibilang ng rate limiter
  skipSuccessfulRequests: false 
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests generated from this IP, please try again later.'
});

module.exports = { loginLimiter, apiLimiter };