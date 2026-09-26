# CYBERTECH - Advanced Email Threat Intelligence & Forensic Platform

This repository contains the complete **CyberTech** frontend and Python/Flask backend integrated with **Google OAuth 2.0** and the **Google Gmail API (`gmail.readonly`)**.

---

## 📁 Project Structure

```text
cybertech/
├── app.py                  # Flask backend with OAuth2 & Gmail API endpoints
├── gmail_service.py        # Helper module for OAuth flow, MIME parsing, and RFC-822 reconstruction
├── requirements.txt        # Production Python dependencies
├── render.yaml             # Render deployment configuration
├── .env.example            # Environment variables template
├── templates/
│   └── index.html          # CyberTech SOC Dashboard (Tailwind CSS, Leaflet, jsPDF, CryptoJS)
└── README.md               # Complete setup, Google Cloud & Render deployment guide
```

---

## 🛠️ Required Render Environment Variables

When deploying to Render (**https://dashboard.render.com**), navigate to:
**Your Web Service** → **Environment** → **Environment Variables** and add the following:

| Variable Name | Required | Example / Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | **Yes** | A random 32-character string for securing Flask sessions (e.g. run `python3 -c 'import secrets; print(secrets.token_hex(32))'`) |
| `GOOGLE_CLIENT_ID` | **Yes** | Your Google Cloud OAuth 2.0 Web Client ID (e.g. `587350731847-xxxxxxxx.apps.googleusercontent.com`) |
| `GOOGLE_CLIENT_SECRET` | **Yes** | Your Google Cloud OAuth 2.0 Web Client Secret (e.g. `GOCSPX-xxxxxxxxxxxxxx`) |
| `REDIRECT_URI` | **Yes** | `https://cybertechx.onrender.com/oauth2callback` |

> 🔒 **Security Notice:**
> Never commit `GOOGLE_CLIENT_SECRET` or `SECRET_KEY` to public Git repositories. Tokens and secrets are handled exclusively on the backend and are never exposed to browser JavaScript or localStorage.

---

## 🌐 Google Cloud Console Setup

### 1. Enable the Gmail API
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Select your project (or create a new one, e.g., `CyberTech-Threat-Platform`).
3. Navigate to **APIs & Services** → **Library**.
4. Search for **Gmail API** and click **Enable**.

### 2. Configure OAuth Consent Screen
1. Navigate to **APIs & Services** → **OAuth consent screen**.
2. Select **External** and click **Create**.
3. Enter App information:
   - **App name:** `CyberTech`
   - **User support email:** Your email address
   - **Developer contact information:** Your email address
4. Under **Scopes**, click **Add or Remove Scopes** and add:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `openid`
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
5. Under **Test users** (while in "Testing" publishing status):
   - Click **+ Add Users** and enter the Gmail accounts you want to test with (e.g., your personal or test Gmail).
   - *Note:* While your app is in "Testing" mode, only accounts listed here can connect. Once verified or made public, anyone can connect.

### 3. Create OAuth 2.0 Web Client Credentials
1. Navigate to **APIs & Services** → **Credentials**.
2. Click **+ Create Credentials** → **OAuth client ID**.
3. Choose **Application type:** `Web application`.
4. Set **Name:** `CyberTech Web Client`.
5. Under **Authorized JavaScript origins**, add:
   ```text
   https://cybertechx.onrender.com
   http://localhost:5000
   ```
6. Under **Authorized redirect URIs**, add:
   ```text
   https://cybertechx.onrender.com/oauth2callback
   http://localhost:5000/oauth2callback
   ```
7. Click **Create** and copy your **Client ID** and **Client Secret**.

---

## 🚀 Render Deployment Steps

1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Add CyberTech Gmail integration"
   git remote add origin https://github.com/your-username/cybertech.git
   git push -u origin main
   ```

2. **Connect to Render:**
   - Log into [Render](https://dashboard.render.com).
   - Click **New +** → **Web Service**.
   - Select your GitHub repository.

3. **Configure the Web Service:**
   - **Name:** `cybertechx`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** `Free`

4. **Add Environment Variables:**
   - Add `SECRET_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `REDIRECT_URI` as listed in the table above.

5. Click **Create Web Service**. Once deployed, your site will be live at:
   **`https://cybertechx.onrender.com`**

---

## 💻 Local Development & Testing

1. **Clone and enter the directory:**
   ```bash
   cd cybertech
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Create your local `.env` file:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in your `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
   Set `REDIRECT_URI=http://localhost:5000/oauth2callback` and uncomment `OAUTHLIB_INSECURE_TRANSPORT=1`.

4. **Run the local development server:**
   ```bash
   python3 app.py
   ```
   Open **`http://localhost:5000`** in your browser.

---

## 🧪 Testing Steps

1. Open `https://cybertechx.onrender.com` (or `http://localhost:5000`).
2. Click the **Connect Gmail** button in the navbar or left mailbox section.
3. You will be redirected to Google's consent screen. Select your authorized Gmail account and grant read-only access.
4. Google redirects back to `/oauth2callback`. The dashboard updates to:
   ```text
   Gmail Connected ✓
   Connected account: example@gmail.com
   ```
5. Your recent inbox messages appear in the mailbox feed.
6. Click **[ View ]** on any email to inspect headers (`Message-ID`, `Return-Path`, `Received`, `SPF`, `DKIM`, `DMARC`), attachments metadata, URLs, and message body.
7. Click **[ View Raw RFC-822 ]** or **[ Download .eml ]** to retrieve the unmodified email representation.
8. Click **[ Analyze ]** to pass the message into the CyberTech heuristic engine:
   - View the calculated Threat Score, Detection Matrix, and Network Origin Telemetry.
   - Click **[ View Origin Map ]** to inspect relay hops on the Leaflet map.
   - Click **[ Download PDF ]** to export the Section 65B forensic certificate.
   - Click **[ Report to SOC ]** to dispatch the alert.
9. Click **[ Disconnect ]** to revoke application credentials and return to disconnected state.

---

## ⚠️ Common OAuth Errors & Troubleshooting

| Error | Root Cause | Fix |
| :--- | :--- | :--- |
| `redirect_uri_mismatch` (400) | The redirect URI sent by the app doesn't match Google Cloud Console. | Ensure `https://cybertechx.onrender.com/oauth2callback` is added to **Authorized redirect URIs** in Google Cloud Console. Double check protocol (`https` vs `http`) and trailing slashes. |
| `access_denied` | The user clicked "Cancel" on the Google consent screen. | Normal user rejection. CyberTech shows "Gmail connection cancelled." |
| `403 Access blocked: CyberTech has not completed the Google verification process` | The Google Cloud project is in **Testing** mode and the logging-in email is not added as a Test User. | In Google Cloud Console → **OAuth consent screen** → **Test users**, click **+ Add Users** and add your email. |
| `Token has been expired or revoked` | The OAuth refresh token was invalidated or expired. | Click **Disconnect** in CyberTech and reconnect to generate fresh tokens. |
| `Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET` | Environment variables are not set. | Add both keys under **Environment Variables** in Render Dashboard. |
