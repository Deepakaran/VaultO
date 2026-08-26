const nodemailer = require('nodemailer');

// Create a reusable transporter using Gmail SMTP.
// Use an App Password (not your real password) with Gmail.
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Sends an OTP email to the specified address.
 * @param {string} to      - Recipient email
 * @param {string} otp     - Plain-text 6-digit OTP
 * @param {string} purpose - 'signup' | 'login' | 'reset'
 */
const sendOtpEmail = async (to, otp, purpose = 'login') => {
  const subjects = {
    signup: 'VaultO – Verify Your Email',
    login:  'VaultO – Your Login OTP',
    reset:  'VaultO – Password Reset OTP',
  };

  const actionText = {
    signup: 'complete your registration',
    login:  'log in to your account',
    reset:  'reset your password',
  };

  const mailOptions = {
    from: `"VaultO" <${process.env.EMAIL_USER}>`,
    to,
    subject: subjects[purpose] || 'VaultO – Your OTP',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;
                  border:1px solid #e0e0e0;border-radius:8px;padding:32px;
                  background:#ffffff;">
        <h2 style="color:#4f46e5;margin-bottom:8px;">VaultO</h2>
        <p style="color:#374151;">
          Use the OTP below to ${actionText[purpose] || 'proceed'}:
        </p>
        <div style="font-size:36px;font-weight:bold;letter-spacing:8px;
                    color:#111827;text-align:center;padding:24px 0;">
          ${otp}
        </div>
        <p style="color:#6b7280;font-size:13px;">
          This code expires in <strong>5 minutes</strong>. Do not share it with anyone.
        </p>
        <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;" />
        <p style="color:#9ca3af;font-size:12px;">
          If you did not request this code, please ignore this email.
        </p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};

module.exports = { sendOtpEmail };
