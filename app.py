"""
CyberTech - Advanced Email Threat Intelligence & Forensic Platform
Flask Backend with Google OAuth 2.0 & Gmail API Integration.
"""

import os
import secrets
from typing import Dict, Any, Optional

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
    send_from_directory,
)
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# For local development over HTTP (auto-enabled if running on localhost)
if os.environ.get("FLASK_ENV") == "development" or os.environ.get("OAUTHLIB_INSECURE_TRANSPORT") == "1":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from gmail_service import (
    create_oauth_flow,
    credentials_to_dict,
    dict_to_credentials,
    get_gmail_service,
    get_user_profile,
    list_messages,
    get_message_raw,
    parse_message_full,
)

app = Flask(__name__, template_folder="templates", static_folder="static")

# Secret key configuration for secure session management
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Session security attributes
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def get_configured_redirect_uri() -> str:
    """
    Determine the redirect URI.
    Uses REDIRECT_URI env variable if provided.
    Otherwise automatically falls back to current host or default production Render URI.
    """
    env_uri = os.environ.get("REDIRECT_URI", "").strip()
    if env_uri:
        return env_uri

    host = request.host.lower()
    if "localhost" in host or "127.0.0.1" in host:
        return f"{request.scheme}://{request.host}/oauth2callback"

    return "https://cybertechx.onrender.com/oauth2callback"


@app.route("/")
def index():
    """Render CyberTech Forensic Dashboard."""
    connected_email = session.get("user_email")
    is_connected = bool(session.get("credentials") and connected_email)
    google_configured = bool(
        os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")
    )
    return render_template(
        "index.html",
        is_connected=is_connected,
        connected_email=connected_email or "",
        google_configured=google_configured,
    )


@app.route("/auth/google")
@app.route("/connect-gmail")
def connect_gmail():
    """
    Initiate Google OAuth 2.0 authorization flow.
    Generates state token for CSRF protection and redirects to Google's consent screen.
    """
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        return redirect(url_for("index", oauth_error="missing_credentials"))

    redirect_uri = get_configured_redirect_uri()
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_redirect_uri"] = redirect_uri

    try:
        flow = create_oauth_flow(redirect_uri, state=state)
        authorization_url, _ = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true",
        )
        return redirect(authorization_url)
    except Exception as e:
        app.logger.error("Failed to initialize Google OAuth flow: %s", str(e))
        return redirect(url_for("index", oauth_error="flow_init_failed"))


@app.route("/oauth2callback")
def oauth2callback():
    """
    Google OAuth 2.0 callback endpoint.
    Verifies state token, exchanges authorization code for tokens,
    retrieves the authenticated email address, and persists session.
    """
    # 1. Check for errors returned by Google
    error = request.args.get("error")
    if error:
        if error == "access_denied":
            return redirect(url_for("index", status="cancelled"))
        return redirect(url_for("index", status="oauth_error", error=error))

    # 2. Verify CSRF state token
    state = request.args.get("state")
    saved_state = session.get("oauth_state")
    if not state or state != saved_state:
        app.logger.warning("OAuth state mismatch: received=%s, saved=%s", state, saved_state)
        return redirect(url_for("index", status="oauth_error", error="state_mismatch"))

    code = request.args.get("code")
    if not code:
        return redirect(url_for("index", status="oauth_error", error="missing_code"))

    redirect_uri = session.get("oauth_redirect_uri") or get_configured_redirect_uri()

    try:
        flow = create_oauth_flow(redirect_uri, state=state)
        # Exchange code for credentials
        flow.fetch_token(code=code)
        credentials = flow.credentials

        # Store credentials securely in server-side session
        session["credentials"] = credentials_to_dict(credentials)

        # Build Gmail API client and obtain authenticated email address
        service, _ = get_gmail_service(session["credentials"])
        user_email = get_user_profile(service)
        session["user_email"] = user_email

        return redirect(url_for("index", status="connected"))
    except Exception as e:
        app.logger.error("Error exchanging OAuth code: %s", str(e))
        return redirect(url_for("index", status="oauth_error", error="token_exchange_failed"))


@app.route("/api/gmail/status")
def gmail_status():
    """Return JSON status of the Gmail connection."""
    has_creds = bool(session.get("credentials"))
    user_email = session.get("user_email")
    return jsonify({
        "connected": has_creds and bool(user_email),
        "email": user_email if has_creds else None,
    })


@app.route("/api/gmail/disconnect", methods=["POST"])
def disconnect_gmail():
    """Disconnect Gmail account and invalidate session credentials."""
    session.pop("credentials", None)
    session.pop("user_email", None)
    session.pop("oauth_state", None)
    session.pop("oauth_redirect_uri", None)
    return jsonify({"success": True, "message": "Gmail account disconnected successfully."})


@app.route("/api/gmail/emails")
def fetch_emails():
    """
    Fetch recent emails from the authenticated user's Gmail mailbox.
    Supports pagination (pageToken) and search queries (q).
    """
    cred_dict = session.get("credentials")
    if not cred_dict:
        return jsonify({"error": "Gmail is not connected. Please authenticate first."}), 401

    try:
        service, refreshed_data = get_gmail_service(cred_dict)
        if refreshed_data:
            session["credentials"] = refreshed_data
    except Exception as e:
        app.logger.error("Failed to build Gmail service: %s", str(e))
        return jsonify({"error": "Unable to connect to Gmail right now. Please try again."}), 503

    max_results = request.args.get("maxResults", 20, type=int)
    page_token = request.args.get("pageToken", None)
    query = request.args.get("q", None)

    try:
        list_response = list_messages(
            service=service,
            max_results=max_results,
            page_token=page_token,
            query=query,
        )
    except Exception as e:
        app.logger.error("Error listing Gmail messages: %s", str(e))
        return jsonify({"error": "Unable to connect to Gmail right now. Please try again."}), 503

    message_summaries = list_response.get("messages", [])
    parsed_emails = []

    # Fetch details for each message
    for msg_meta in message_summaries:
        msg_id = msg_meta.get("id")
        if not msg_id:
            continue
        try:
            full_msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
            parsed = parse_message_full(full_msg)
            parsed_emails.append(parsed)
        except Exception as e:
            app.logger.warning("Failed to fetch details for message %s: %s", msg_id, str(e))
            continue

    return jsonify({
        "emails": parsed_emails,
        "nextPageToken": list_response.get("nextPageToken"),
        "resultSizeEstimate": list_response.get("resultSizeEstimate", len(parsed_emails)),
    })


@app.route("/api/gmail/emails/<message_id>/raw")
def fetch_email_raw(message_id: str):
    """
    Fetch authentic raw RFC-822 message representation for forensic evaluation.
    """
    cred_dict = session.get("credentials")
    if not cred_dict:
        return jsonify({"error": "Gmail is not connected. Please authenticate first."}), 401

    try:
        service, refreshed_data = get_gmail_service(cred_dict)
        if refreshed_data:
            session["credentials"] = refreshed_data
        raw_text, _ = get_message_raw(service, message_id)
        return jsonify({"id": message_id, "raw": raw_text})
    except Exception as e:
        app.logger.error("Error retrieving raw message %s: %s", message_id, str(e))
        return jsonify({"error": "This email could not be retrieved."}), 404


@app.route("/api/gmail/emails/<message_id>/download-eml")
def download_eml(message_id: str):
    """
    Download message as a raw authentic .eml file.
    """
    cred_dict = session.get("credentials")
    if not cred_dict:
        return jsonify({"error": "Gmail is not connected. Please authenticate first."}), 401

    try:
        service, refreshed_data = get_gmail_service(cred_dict)
        if refreshed_data:
            session["credentials"] = refreshed_data
        _, raw_bytes = get_message_raw(service, message_id)
        return Response(
            raw_bytes,
            mimetype="message/rfc822",
            headers={
                "Content-Disposition": f'attachment; filename="cybertech_forensic_{message_id}.eml"'
            },
        )
    except Exception as e:
        app.logger.error("Error generating .eml for %s: %s", message_id, str(e))
        return jsonify({"error": "This email could not be retrieved."}), 404


if __name__ == "__main__":
    # Local development server
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
