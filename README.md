# Secure Login System

A Node.js/Express login application built around the supplied internship task and video transcript.

## Included security controls

- Joi validation for registration and login inputs.
- bcryptjs password hashing (12 salt rounds) and password comparison.
- SQLite prepared statements (`?` placeholders) to avoid SQL injection.
- express-session with a SQLite-backed session store; HttpOnly and SameSite cookies.
- Helmet security headers and a Content Security Policy.
- Rate limiting on registration, login and 2FA verification.
- dotenv for configuration and Winston security/error logging.
- Optional authenticator-app 2FA using TOTP and a QR code.
- Generic production error responses.

## Requirements

- Node.js 20 or newer
- npm (installed with Node.js)

## Run on Windows PowerShell

1. Extract the ZIP file.
2. Open PowerShell in the extracted `secure-login-system` folder.
3. Check versions:

   ```powershell
   node -v
   npm -v
   ```

4. Create your environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

5. Open `.env` and replace `SESSION_SECRET` with a long random value (at least 32 characters).
6. Install packages:

   ```powershell
   npm install
   ```

7. Start the server:

   ```powershell
   npm start
   ```

8. Open **http://localhost:3000** in your browser.

## Test the application

1. Select **Create account** and register with a name, valid email and a password containing uppercase, lowercase, a number and a special character (minimum 8 characters).
2. Return to **Sign in** and log in with the same details.
3. Confirm the dashboard displays your account.
4. Select **Set up 2FA**, scan the QR code with an authenticator app, and enter the current six-digit code.
5. Sign out and sign in again. The application should ask for a 2FA code.
6. Test a wrong password and repeated login attempts; the app should reject them and apply rate limiting.

## Project files

- `server.js` — Express server, API routes, database access and security controls.
- `public/index.html` — application interface.
- `public/styles.css` — responsive styling.
- `public/app.js` — browser-side interactions.
- `.env.example` — environment variable template.
- `data/` — SQLite user and session databases are created automatically.
- `logs/security.log` — application/security logs are created automatically.

## Important deployment notes

This is a local internship/demo project. Before public production deployment, serve it behind HTTPS, set `NODE_ENV=production`, use a strong secret stored by your hosting provider, review the Content Security Policy, configure backups and monitoring, and keep dependencies patched. The app enables secure cookies in production mode; do not expose a production login over plain HTTP.

The transcript also discusses dependency auditing. Run `npm audit` to inspect advisories and review any suggested updates before applying them. Avoid blindly using `npm audit fix --force`, because it can introduce breaking package upgrades.
