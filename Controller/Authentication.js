import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { validationResult } from "express-validator";
import db from "../server.js";
import crypto from "crypto";
import appError from "./../utils/AppError.js";
import catchAsync from "./../utils/catchAsync.js";
import verification from "./emailService.js";
import { SlowBuffer } from "buffer";
import { error } from "console";

export const creatSentSessionToken = (user, statusCode, message, req, res) => {
  req.session.regenerate((err) => {
    if (err) res.status(400).json({ message: "Failed Generating Token" });
    req.session.user = { id: user.id, role: user.role || "user" };
    res.status(statusCode).json({ message });
  });
};

// Based Role Access Control
export const roleMiddleWare = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(401).json({ message: "Access denied" });
    }
    next();
  };
};

export const authenticationMiddleWare = catchAsync(async (req, res, next) => {
  const user = req.session.user;

  if (!user) return next(new appError("Access denied. No token provided", 401));

  req.user = user;
  next();
});

export const register = catchAsync(async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return next(new appError(`${errors.array()}`, 400));

  const { name, email, password } = req.body;
  const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  const hashedPassword = await bcrypt.hash(password, 10);
  let sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
  await db.query(sql, [name, email, hashedPassword]);

  sql = "SELECT id, role FROM users WHERE email=?";
  const result = await db.query(sql, [email]);
  const { id, role } = result[0][0];
  const user = { id, role };

  verification.sendVerificationEmail(email, verificationToken);

  creatSentSessionToken(user, 200, "Registered and logged in successfully", req, res);
});

export const login = catchAsync(async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const message = errors.errors[0].msg;
    return next(new appError(message, 400));
  }

  const { email, password } = req.body;
  let sql = "SELECT id, role, lock_until, verifed, password, mfa_enabled, failed_attempts FROM users WHERE email = ?";
  const [rows] = await db.query(sql, [email]);

  if (!rows.length) return next(new appError("User not found", 404));

  const user = rows[0];

  if (user.lock_until && new Date() < new Date(user.lock_until))
    return next(new appError(`Your account is locked until ${user.lock_until}`, 403));

  if (!user.verifed)
    return next(new appError("Email not verified. Please verify your email", 403));

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    const failedAttempt = user.failed_attempts + 1;
    let lock = null;
    if (failedAttempt > 5) {
      lock = new Date(Date.now() + 15 * 60 * 1000);
      verification.sendLockNotification(email);
    }

    sql = "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE email = ?";
    await db.query(sql, [failedAttempt, lock, email]);
    return next(
      new appError(
        `Invalid credentials. Attempts left: ${failedAttempt < 5 ? 5 - failedAttempt : 0}`,
        400
      )
    );
  }

  sql = "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE email = ?";
  await db.query(sql, [email]);

  if (user.mfa_enabled) {
    req.session.tempUserId = user.id;
    return res.status(200).json({ message: "OTP is required" });
  }

  creatSentSessionToken(user, 200, "Logged in successfully", req, res);
});

export const forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString("hex");
  const hashed_token = crypto.createHash("sha256").update(token).digest("hex");
  const token_expiry = new Date(Date.now() + 15 * 60 * 1000);
  const sql = "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?";
  const [rows] = await db.query(sql, [hashed_token, token_expiry, email]);

  if (rows.affectedRows === 0) return next(new appError("User not found", 400));

  try {
    verification.sendVerificationPassword(email, token);
    res.status(200).json({ message: "Reset email sent" });
  } catch (err) {
    const sql = "UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE email = ?";
    await db.query(sql);
    return next(new appError("Error sending email. Try again later", 500));
  }
});

export const resetPassword = catchAsync(async (req, res, next) => {
  const { token } = req.query;
  const { newPassword, passwordConfirm } = req.body;

  if (newPassword !== passwordConfirm)
    return next(new appError("New password and confirm password must match", 400));

  const hashed_token = crypto.createHash("sha256").update(token).digest("hex");
  let sql = "SELECT id, role FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()";
  const [rows] = await db.query(sql, [hashed_token]);

  if (!rows.length) return next(new appError("Invalid or expired reset link", 400));

  const user = rows[0];
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  sql = "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?";
  await db.query(sql, [hashedPassword, user.id]);

  req.session.regenerate((err) => {
    if (err) return res.status(400).json({ error: err });
    req.session.user = { id: user.id, role: user.role };
    res.status(200).json({ message: "Password changed successfully" });
  });
});

export const sendVerificationToEmail = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  const [rows] = await db.query(sql, [email]);

  if (!rows.length) return next(new appError("User not found", 400));
  const user = rows[0];

  if (user.verifed)
    return next(new appError("Email is already verified", 400));

  const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });

  verification.sendVerificationEmail(email, verificationToken);
  res.json({ message: "New verification email sent." });
});

export const verifyEmail = catchAsync(async (req, res, next) => {
  const { token } = req.query;
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const email = decoded.email;
  const sql = "UPDATE users SET verifed = 1 WHERE email = ?";
  await db.query(sql, [email]);
  res.status(200).json({ message: "Email verified" });
});

export const logout = catchAsync(async (req, res, next) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.status(200).json({ message: "Logged out successfully" });
  });
});

export const updatePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword, passwordConfirm } = req.body;
  if (newPassword !== passwordConfirm)
    return next(new appError("New password and confirm password must match", 400));

  const { id } = req.user;
  const [rows] = await db.query("SELECT password, role FROM users WHERE id = ?", [id]);

  const { password } = rows[0];
  const verify = await bcrypt.compare(currentPassword, password);
  if (!verify) return next(new appError("Current password incorrect", 400));

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await db.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, id]);

  creatSentSessionToken(rows[0], 200, "Password changed successfully", req, res);
  delete req.user;
});

export default {
  creatSentSessionToken,
  roleMiddleWare,
  authenticationMiddleWare,
  register,
  login,
  forgotPassword,
  resetPassword,
  sendVerificationToEmail,
  verifyEmail,
  logout,
  updatePassword
};


