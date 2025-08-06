import speakeasy from "speakeasy";
import QRcode from "qrcode";
import db from "../../server.js";
import AppError from "../../utils/AppError.js";
import catchAsync from "../../utils/catchAsync.js";
import { creatSentSessionToken } from "../Authentication.js";

export const enableMfa = catchAsync(async (req, res, next) => {
  // Generate the secret
  const secret = speakeasy.generateSecret({ length: 25 });

  // Change the MFA status in the database
  const sql = "UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?";
  await db.query(sql, [secret.base32, req.user.id]);

  QRcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    if (err) return next(new AppError(err, 400));
    res.status(200).json({ secret: secret.base32, QRcode: data_url });
  });
});

export const disableMfa = catchAsync(async (req, res) => {
  const sql =
    "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?";
  await db.query(sql, [req.user.id]);
  res.status(200).json({
    message: "Multi-Factor Authentication disabled successfully",
  });
});

export const verifyOtp = catchAsync(async (req, res, next) => {
  const { otp } = req.body;
  const userId = req.session.tempUserId;

  const sql = "SELECT id,role,mfa_secret FROM users WHERE id = ?";
  const [user] = await db.query(sql, [userId]);

  const { mfa_secret } = user[0];

  const verified = speakeasy.totp.verify({
    secret: mfa_secret,
    encoding: "base32",
    token: otp,
  });

  if (!verified) {
    return next(new AppError("Invalid OTP, please try again", 400));
  }

  delete req.session.tempUserId;
  creatSentSessionToken(user[0], 200, "Logged in successfully", req, res);
});

// Optional default export
export default {
  enableMfa,
  disableMfa,
  verifyOtp,
};
