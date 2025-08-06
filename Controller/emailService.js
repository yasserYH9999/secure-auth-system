import nodemailer from "nodemailer";

// Create the transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Send verification email
export const sendVerificationEmail = async (email, verificationToken) => {
  const verificationLink = `http://127.0.0.1:3000/api/email-verification?token=${verificationToken}`;
  const emailHTML = `
    <h2>Verify Your Email</h2>
    <p>Click the button below to verify your email:</p>
    <a href="${verificationLink}" style="padding:10px 20px; background:#28a745; color:#fff; text-decoration:none;">Verify Email</a>
    <p>If you didn't sign up, ignore this email.</p>
  `;

  const mailOptions = {
    from: "yasseryahyabey",
    to: email,
    subject: "Email Verification",
    html: emailHTML,
  };

  await transporter.sendMail(mailOptions);
};

// Send password reset email
export const sendVerificationPassword = async (email, token) => {
  const resetLink = `http://127.0.0.1:3000/api/reset-password?token=${token}`;
  const emailHTML = `
    <div style="max-width: 500px; margin: auto; padding: 20px; font-family: Arial, sans-serif;">
        <h2>Password Reset Request</h2>
        <p>Click the button below to reset your password:</p>
        <a href="${resetLink}" style="display:inline-block; padding:12px 20px; background:#007BFF; color:#fff; text-decoration:none; border-radius:5px;">Reset Password</a>
        <p>If you didn't request this, please ignore this email.</p>
        <p>&copy; 2025 Node X.</p>
    </div>
  `;

  const mailOptions = {
    from: "yasseryahyabey",
    to: email,
    subject: "API Password Reset",
    html: emailHTML,
  };

  await transporter.sendMail(mailOptions);
};

// Send account lock notification email
export const sendLockNotification = async (email) => {
  const html = `
    <div style="max-width: 500px; margin: auto; padding: 20px; font-family: Arial, sans-serif;">
        <h2 style="color: #d9534f;">⚠ Account Locked Due to Failed Attempts</h2>
        <p>Dear User,</p>
        <p>Your account has been temporarily locked due to multiple unsuccessful login attempts.</p>
        <p>If this was not you, please reset your password immediately to secure your account.</p>
        <p>You can unlock your account by following the instructions in our help center.</p>
        <a href="http://127.0.0.1:3000/api/unlock-account" 
           style="display:inline-block; padding:12px 20px; background:#007BFF; color:#fff; text-decoration:none; border-radius:5px;">
           Unlock My Account
        </a>
        <p>If you need further assistance, contact our support team.</p>
        <p>&copy; 2025 Node X.</p>
    </div>
  `;

  const mailOptions = {
    from: "Node x Security",
    to: email,
    subject: "🚨 Your Account Has Been Locked",
    html: html,
  };

  await transporter.sendMail(mailOptions);
};

// Export all as default object
export default {
  sendVerificationEmail,
  sendVerificationPassword,
  sendLockNotification,
};
