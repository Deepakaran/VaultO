/**
 * mailService.js
 * ─────────────────────────────────────────────────────────────────────
 * Nodemailer-based email service for VaultO.
 *
 * Exports:
 *   sendOtpEmail(email, otp, purpose) — sends a real OTP email via Gmail SMTP
 *
 * Configuration (via .env):
 *   EMAIL_USER  — Gmail sender address  (e.g. vaulto.noreply@gmail.com)
 *   EMAIL_PASS  — Gmail App Password    (NOT your normal Gmail password)
 * ─────────────────────────────────────────────────────────────────────
 */

'use strict';

const nodemailer = require('nodemailer');

// ── Purpose metadata ──────────────────────────────────────────────────
const PURPOSES = {
  signup: { label: 'Email Verification', action: 'complete your registration'  },
  login:  { label: 'Login',              action: 'log in to your account'       },
  reset:  { label: 'Password Reset',     action: 'reset your password'          },
};

// ── Transporter (created once, reused across calls) ───────────────────
// Uses Gmail SMTP with an App Password.
// Lazy-initialise so the module loads fine even before .env is parsed.
let _transporter = null;

function getTransporter() {
  if (_transporter) return _transporter;

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error(
      '[mailService] EMAIL_USER and EMAIL_PASS must be set in your .env file.'
    );
  }

  _transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,   // Gmail App Password (16-char, no spaces)
    },
  });

  return _transporter;
}

// ── HTML email template ───────────────────────────────────────────────
function buildHtml(otp, meta, expiresAt) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VaultO OTP</title>
</head>
<body style="margin:0;padding:0;background:#f4f7fb;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7fb;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;border:1px solid #e2eaf3;overflow:hidden;box-shadow:0 4px 24px rgba(13,33,55,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0d2137 0%,#1a3a55 100%);padding:32px 40px;text-align:center;">
              <div style="font-size:26px;font-weight:800;letter-spacing:5px;color:#ffffff;">VAULT<span style="color:#0ba888;">O</span></div>
              <div style="font-size:11px;letter-spacing:3px;color:rgba(255,255,255,0.5);margin-top:4px;text-transform:uppercase;">Secure Exam Delivery</div>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 32px;">
              <p style="margin:0 0 8px;font-size:13px;letter-spacing:2px;color:#0ba888;text-transform:uppercase;font-weight:600;">${meta.label} OTP</p>
              <h2 style="margin:0 0 20px;font-size:22px;color:#0d2137;font-weight:700;">Use this OTP to ${meta.action}</h2>
              <p style="margin:0 0 28px;font-size:14px;color:#5a7a96;line-height:1.6;">
                You (or someone) requested a one-time password for your VaultO account.
                Enter the code below to proceed. <strong>Do not share this code with anyone.</strong>
              </p>

              <!-- OTP box -->
              <div style="background:#f4f7fb;border:2px dashed #0ba888;border-radius:12px;padding:24px;text-align:center;margin-bottom:28px;">
                <div style="font-size:42px;font-weight:800;letter-spacing:14px;color:#0d2137;font-family:'Courier New',monospace;">${otp}</div>
                <div style="margin-top:10px;font-size:12px;color:#5a7a96;">Valid until <strong>${expiresAt}</strong> &nbsp;·&nbsp; 5 minutes</div>
              </div>

              <!-- Warning -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff8e6;border:1px solid #f59e0b;border-radius:10px;margin-bottom:28px;">
                <tr>
                  <td style="padding:14px 18px;">
                    <span style="font-size:13px;color:#92400e;">
                      ⚠️&nbsp; If you did not request this OTP, please ignore this email.
                      Your account remains secure.
                    </span>
                  </td>
                </tr>
              </table>

              <p style="margin:0;font-size:13px;color:#5a7a96;line-height:1.6;">
                This is an automated message. Please do not reply to this email.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f4f7fb;border-top:1px solid #e2eaf3;padding:20px 40px;text-align:center;">
              <p style="margin:0;font-size:11px;color:#9baab8;">
                © ${new Date().getFullYear()} VaultO · Secure Exam Delivery Platform<br>
                This OTP expires in 5 minutes and is single-use only.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ── Plain-text fallback ───────────────────────────────────────────────
function buildText(otp, meta, expiresAt) {
  return [
    `VaultO — ${meta.label} OTP`,
    '─'.repeat(40),
    '',
    `Your OTP to ${meta.action}:`,
    '',
    `      ${otp}`,
    '',
    `Valid until: ${expiresAt} (5 minutes)`,
    '',
    'Do NOT share this OTP with anyone.',
    'If you did not request this, please ignore this email.',
    '',
    '─'.repeat(40),
    'VaultO · Secure Exam Delivery',
  ].join('\n');
}

// ── Public API ────────────────────────────────────────────────────────
/**
 * Sends a real OTP email via Gmail SMTP.
 * Console-logs the OTP regardless (useful during development).
 *
 * @param {string} email   - Recipient address
 * @param {string} otp     - Plain-text 6-digit OTP (already generated)
 * @param {string} purpose - 'signup' | 'login' | 'reset'
 * @returns {Promise<{ success: boolean, message: string }>}
 */
async function sendOtpEmail(email, otp, purpose = 'login') {
  const meta      = PURPOSES[purpose] || { label: purpose, action: 'proceed' };
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toLocaleTimeString(
    'en-IN', { hour: '2-digit', minute: '2-digit', hour12: true }
  );

  // ── Always log to console for easy testing ────────────────────────
  const line = '─'.repeat(52);
  console.log(`\n📧  [EMAIL] ─── ${meta.label} OTP`);
  console.log(line);
  console.log(`  To      : ${email}`);
  console.log(`  Subject : VaultO – Your ${meta.label} OTP`);
  console.log(`              ┌──────────────┐`);
  console.log(`              │   ${otp}   │`);
  console.log(`              └──────────────┘`);
  console.log(`  Expires : ${expiresAt}  (5 minutes from now)`);
  console.log(line + '\n');

  // ── Send via Gmail SMTP ───────────────────────────────────────────
  try {
    const transporter = getTransporter();

    await transporter.sendMail({
      from:    `"VaultO Security" <${process.env.EMAIL_USER}>`,
      to:      email,
      subject: `VaultO – Your ${meta.label} OTP`,
      text:    buildText(otp, meta, expiresAt),
      html:    buildHtml(otp, meta, expiresAt),
    });

    return {
      success: true,
      message: `OTP sent to ${email}. It expires in 5 minutes.`,
    };
  } catch (err) {
    // Log full SMTP error but don't expose it to the client
    console.error('[mailService] Failed to send email:', err.message);
    return {
      success: false,
      message: 'Failed to send OTP email. Please try again.',
      _error:  err.message,   // internal, strip before sending to client
    };
  }
}

// ── Credentials email HTML ────────────────────────────────────────────
function buildCredentialsHtml(instituteId, password, name) {
  const displayName = name ? name : 'Institute';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VaultO – Institute Credentials</title>
</head>
<body style="margin:0;padding:0;background:#f4f7fb;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7fb;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;border:1px solid #e2eaf3;overflow:hidden;box-shadow:0 4px 24px rgba(13,33,55,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0d2137 0%,#1a3a55 100%);padding:32px 40px;text-align:center;">
              <div style="font-size:26px;font-weight:800;letter-spacing:5px;color:#ffffff;">VAULT<span style="color:#0ba888;">O</span></div>
              <div style="font-size:11px;letter-spacing:3px;color:rgba(255,255,255,0.5);margin-top:4px;text-transform:uppercase;">Secure Exam Delivery</div>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 32px;">
              <p style="margin:0 0 8px;font-size:13px;letter-spacing:2px;color:#0ba888;text-transform:uppercase;font-weight:600;">Welcome to VaultO</p>
              <h2 style="margin:0 0 20px;font-size:22px;color:#0d2137;font-weight:700;">Your Institute Account is Ready</h2>
              <p style="margin:0 0 28px;font-size:14px;color:#5a7a96;line-height:1.6;">
                Dear <strong>${displayName}</strong>, your VaultO institute account has been created by the system administrator.
                Use the credentials below to sign in to your institute portal.
              </p>

              <!-- Credentials box -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7fb;border:2px solid #0ba888;border-radius:12px;margin-bottom:28px;overflow:hidden;">
                <tr>
                  <td style="padding:20px 28px;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding:10px 0;border-bottom:1px solid #e2eaf3;">
                          <span style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#5a7a96;font-weight:600;">Institute ID</span><br>
                          <span style="font-size:24px;font-weight:800;color:#0d2137;letter-spacing:3px;font-family:'Courier New',monospace;">${instituteId}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:10px 0;">
                          <span style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#5a7a96;font-weight:600;">Password</span><br>
                          <span style="font-size:24px;font-weight:800;color:#0d2137;letter-spacing:3px;font-family:'Courier New',monospace;">${password}</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Steps -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#e6f7f3;border:1px solid rgba(11,168,136,0.3);border-radius:10px;margin-bottom:28px;">
                <tr>
                  <td style="padding:16px 20px;">
                    <p style="margin:0 0 8px;font-size:13px;font-weight:600;color:#0d2137;">How to log in:</p>
                    <ol style="margin:0;padding-left:18px;font-size:13px;color:#5a7a96;line-height:2;">
                      <li>Go to the VaultO Institute Portal</li>
                      <li>Enter your registered email address</li>
                      <li>Verify with the OTP sent to your email</li>
                      <li>Enter the <strong>Institute ID</strong> and <strong>Password</strong> above</li>
                    </ol>
                  </td>
                </tr>
              </table>

              <!-- Warning -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff8e6;border:1px solid #f59e0b;border-radius:10px;margin-bottom:28px;">
                <tr>
                  <td style="padding:14px 18px;">
                    <span style="font-size:13px;color:#92400e;">
                      🔒&nbsp; Keep these credentials <strong>confidential</strong>. Do not share them with anyone outside your institution.
                    </span>
                  </td>
                </tr>
              </table>

              <p style="margin:0;font-size:13px;color:#5a7a96;line-height:1.6;">
                This is an automated message. Please do not reply to this email.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f4f7fb;border-top:1px solid #e2eaf3;padding:20px 40px;text-align:center;">
              <p style="margin:0;font-size:11px;color:#9baab8;">
                © ${new Date().getFullYear()} VaultO · Secure Exam Delivery Platform<br>
                This email was sent by the system administrator. If this was unexpected, contact support.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Sends institute credentials (ID + password) to the institute's email.
 * Called after admin OTP is successfully verified during institute creation.
 *
 * @param {string} to          - Institute's email address
 * @param {string} instituteId - Generated institute ID (e.g. INS-4821)
 * @param {string} password    - Plain-text generated password (shown once)
 * @param {string} name        - Institute name (optional)
 * @returns {Promise<{ success: boolean, message: string }>}
 */
async function sendCredentialsEmail(to, instituteId, password, name = '') {
  // ── Console log for dev visibility ────────────────────────────────
  const line = '─'.repeat(52);
  console.log(`\n📧  [EMAIL] ─── Institute Credentials`);
  console.log(line);
  console.log(`  To          : ${to}`);
  console.log(`  Institute ID: ${instituteId}`);
  console.log(`  Password    : ${password}`);
  console.log(line + '\n');

  try {
    const transporter = getTransporter();

    await transporter.sendMail({
      from:    `"VaultO Admin" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'VaultO – Your Institute Account Credentials',
      text: [
        'VaultO – Institute Account Created',
        '─'.repeat(40),
        `Institute: ${name || to}`,
        `Institute ID: ${instituteId}`,
        `Password    : ${password}`,
        '',
        'Log in at the VaultO Institute Portal using your email, OTP, and these credentials.',
        'Keep this information confidential.',
        '─'.repeat(40),
        'VaultO · Secure Exam Delivery',
      ].join('\n'),
      html: buildCredentialsHtml(instituteId, password, name),
    });

    return { success: true, message: `Credentials sent to ${to}.` };
  } catch (err) {
    console.error('[mailService] Failed to send credentials email:', err.message);
    return { success: false, message: 'Failed to send credentials email.', _error: err.message };
  }
}

/**
 * Sends a paper upload confirmation email to the institute.
 * @param {string} to         - Institute email
 * @param {string} paperCode  - Paper code (numbers)
 * @param {string} examName   - Exam / subject name
 * @param {string} examDate   - Formatted exam date string
 * @param {string} unlockTime - Formatted unlock time string
 * @param {string} instituteId - Institute ID
 */
async function sendUploadConfirmationEmail(to, paperCode, examName, examDate, unlockTime, instituteId) {
  const line = '─'.repeat(52);
  console.log(`\n📧  [EMAIL] ─── Paper Upload Confirmation`);
  console.log(line);
  console.log(`  To          : ${to}`);
  console.log(`  Paper Code  : ${paperCode}`);
  console.log(`  Exam Name   : ${examName}`);
  console.log(`  Unlock Time : ${unlockTime}`);
  console.log(line + '\n');

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>VaultO – Paper Upload Confirmed</title></head>
<body style="margin:0;padding:0;background:#f4f7fb;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7fb;padding:40px 0;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;border:1px solid #e2eaf3;overflow:hidden;box-shadow:0 4px 24px rgba(13,33,55,0.08);">
        <tr><td style="background:linear-gradient(135deg,#0d2137 0%,#1a3a55 100%);padding:32px 40px;text-align:center;">
          <div style="font-size:26px;font-weight:800;letter-spacing:5px;color:#ffffff;">VAULT<span style="color:#0ba888;">O</span></div>
          <div style="font-size:11px;letter-spacing:3px;color:rgba(255,255,255,0.5);margin-top:4px;text-transform:uppercase;">Secure Exam Delivery</div>
        </td></tr>
        <tr><td style="padding:40px 40px 32px;">
          <p style="margin:0 0 8px;font-size:13px;letter-spacing:2px;color:#0ba888;text-transform:uppercase;font-weight:600;">Upload Confirmed</p>
          <h2 style="margin:0 0 20px;font-size:22px;color:#0d2137;font-weight:700;">Question Paper Encrypted & Secured</h2>
          <p style="margin:0 0 28px;font-size:14px;color:#5a7a96;line-height:1.6;">
            Institute <strong>${instituteId}</strong>, your question paper has been successfully encrypted using AES-256 and securely stored. It will be available for download at the scheduled unlock time.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7fb;border:2px solid #0ba888;border-radius:12px;margin-bottom:28px;">
            <tr><td style="padding:20px 28px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td style="padding:8px 0;border-bottom:1px solid #e2eaf3;">
                  <span style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#5a7a96;font-weight:600;">Paper Code</span><br>
                  <span style="font-size:22px;font-weight:800;color:#0d2137;letter-spacing:4px;font-family:'Courier New',monospace;">${paperCode}</span>
                </td></tr>
                <tr><td style="padding:8px 0;border-bottom:1px solid #e2eaf3;">
                  <span style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#5a7a96;font-weight:600;">Exam Name</span><br>
                  <span style="font-size:16px;font-weight:600;color:#0d2137;">${examName}</span>
                </td></tr>
                <tr><td style="padding:8px 0;border-bottom:1px solid #e2eaf3;">
                  <span style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#5a7a96;font-weight:600;">Exam Date</span><br>
                  <span style="font-size:14px;font-weight:500;color:#0d2137;">${examDate}</span>
                </td></tr>
                <tr><td style="padding:8px 0;">
                  <span style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#5a7a96;font-weight:600;">Unlock Time</span><br>
                  <span style="font-size:14px;font-weight:500;color:#0ba888;">${unlockTime}</span>
                </td></tr>
              </table>
            </td></tr>
          </table>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#e6f7f3;border:1px solid rgba(11,168,136,0.3);border-radius:10px;margin-bottom:28px;">
            <tr><td style="padding:14px 18px;">
              <p style="margin:0;font-size:13px;color:#0d7a5f;font-weight:600;">🔒 Security Note</p>
              <p style="margin:6px 0 0;font-size:13px;color:#5a7a96;line-height:1.6;">
                Your paper is stored in AES-256-CBC encrypted format. The paper will automatically appear in your institute portal in encrypted form with a live countdown timer. It will only be accessible after the unlock time.
              </p>
            </td></tr>
          </table>
          <p style="margin:0;font-size:13px;color:#5a7a96;">This is an automated confirmation. Do not reply to this email.</p>
        </td></tr>
        <tr><td style="background:#f4f7fb;border-top:1px solid #e2eaf3;padding:20px 40px;text-align:center;">
          <p style="margin:0;font-size:11px;color:#9baab8;">© ${new Date().getFullYear()} VaultO · Secure Exam Delivery Platform</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from:    `"VaultO Security" <${process.env.EMAIL_USER}>`,
      to,
      subject: `VaultO – Paper Upload Confirmed: ${paperCode} | ${examName}`,
      text:    `VaultO Upload Confirmed\nPaper Code: ${paperCode}\nExam: ${examName}\nExam Date: ${examDate}\nUnlock Time: ${unlockTime}\nInstitute: ${instituteId}`,
      html,
    });
    return { success: true };
  } catch (err) {
    console.error('[mailService] Upload confirmation email failed:', err.message);
    return { success: false, _error: err.message };
  }
}

module.exports = { sendOtpEmail, sendCredentialsEmail, sendUploadConfirmationEmail };
