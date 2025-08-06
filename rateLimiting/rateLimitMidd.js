import rateLimit from "express-rate-limit";
import appError from "../utils/AppError.js";
import catchAsync from "../utils/catchAsync.js";

export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 5 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req) => req.ip, // Use the client's IP address as the key
  handler: catchAsync(async (req, res, next) => {
    next(
      new appError(
        `Too many login attempts from this IP (${req.ip}). Try again later.`,
        429
      )
    );
  }),
});

// module.exports = loginLimiter;
export default loginLimiter;