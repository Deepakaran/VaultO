# VaultO Backend – Auth API

Secure authentication REST API built with **Node.js + Express + MongoDB**.

## Quick Start

### 1. Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

| Variable | Description |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `JWT_SECRET` | Secret key for JWT signing |
| `EMAIL_USER` | Gmail address for sending OTPs |
| `EMAIL_PASS` | Gmail [App Password](https://support.google.com/accounts/answer/185833) |
| `CLIENT_URL` | Frontend origin for CORS |

> ⚠️ For Gmail, create an **App Password** – do NOT use your real password.

### 2. Install & run

```bash
npm install
npm run dev      # development (nodemon)
npm start        # production
```

Server starts at **http://localhost:5000**

---

## API Reference

### Admin

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/admin/signup` | `{ email, password, name? }` | Register admin + send signup OTP |
| POST | `/admin/send-otp` | `{ email, purpose }` | Send/resend OTP (`signup`/`login`/`reset`) |
| POST | `/admin/verify-otp` | `{ email, otp }` | Verify signup OTP → mark verified |
| POST | `/admin/login` | `{ email, password, otp }` | 3-factor login → returns JWT |

### Institute

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/institute/login` | `{ email, password, instituteId, otp }` | 4-factor login → returns JWT |

> 📌 To send a login OTP to an institute email, use `/admin/send-otp` with `purpose: "login"` and the institute's email.

### Password Reset

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/forgot-password` | `{ email }` | Send reset OTP |
| POST | `/reset-password` | `{ email, otp, newPassword }` | Verify OTP + set new password |

---

## Security Details

- **Passwords** – bcrypt, 12 salt rounds
- **OTPs** – stored as bcrypt hashes; auto-deleted via MongoDB TTL (5 min)
- **JWT** – HS256, 7-day expiry (configurable)
- **Email enumeration protection** – `/forgot-password` always returns 200

---

## MongoDB Collections

| Collection | Purpose |
|---|---|
| `admins` | Admin accounts |
| `institutes` | Institute accounts |
| `otpstores` | Temporary OTP records (auto-purged in 5 min) |
