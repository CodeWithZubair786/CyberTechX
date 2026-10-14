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
s. |
| `Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET` | Environment variables are not set. | Add both keys under 
