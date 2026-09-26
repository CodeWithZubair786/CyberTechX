"""
CyberTech - Gmail API Integration & Forensics Service Helper
Handles OAuth 2.0 flow, token refreshment, Gmail API queries,
MIME parsing, header extraction, and RFC-822 raw email reconstruction.
"""

import os
import re
import base64
import email
from email.utils import parseaddr
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# OAuth 2.0 Scopes required
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


def get_oauth_config() -> Dict[str, Any]:
    """Retrieve Google OAuth Client Configuration from environment."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        }
    }


def create_oauth_flow(redirect_uri: str, state: Optional[str] = None) -> Flow:
    """Create a Google OAuth2 Flow instance."""
    config = get_oauth_config()
    client_id = config["web"]["client_id"]
    client_secret = config["web"]["client_secret"]

    if not client_id or not client_secret:
        raise ValueError(
            "Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in environment variables."
        )

    flow = Flow.from_client_config(
        client_config=config,
        scopes=GMAIL_SCOPES,
        state=state,
    )
    flow.redirect_uri = redirect_uri
    return flow


def credentials_to_dict(credentials: Credentials) -> Dict[str, Any]:
    """Convert Credentials object to a dictionary for secure session storage."""
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }


def dict_to_credentials(data: Dict[str, Any]) -> Credentials:
    """Recreate Credentials object from session dictionary."""
    return Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri") or "https://oauth2.googleapis.com/token",
        client_id=data.get("client_id") or os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=data.get("client_secret") or os.environ.get("GOOGLE_CLIENT_SECRET"),
        scopes=data.get("scopes") or GMAIL_SCOPES,
    )


def get_gmail_service(cred_dict: Dict[str, Any]) -> Tuple[Any, Optional[Dict[str, Any]]]:
    """
    Build Gmail API client, refreshing expired tokens when necessary.
    Returns (service, updated_credentials_dict_or_None).
    """
    credentials = dict_to_credentials(cred_dict)
    refreshed_data = None

    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            refreshed_data = credentials_to_dict(credentials)
        except Exception as e:
            raise ConnectionError(f"Failed to refresh OAuth token: {str(e)}")

    service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
    return service, refreshed_data


def get_user_profile(service) -> str:
    """Retrieve authenticated user's email address from Gmail API."""
    try:
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress", "Not available")
    except Exception:
        return "Not available"


def list_messages(
    service, max_results: int = 20, page_token: Optional[str] = None, query: Optional[str] = None
) -> Dict[str, Any]:
    """List messages from the user's Gmail mailbox."""
    params: Dict[str, Any] = {
        "userId": "me",
        "maxResults": min(max(max_results, 1), 50),
    }
    if page_token:
        params["pageToken"] = page_token
    if query and query.strip():
        params["q"] = query.strip()

    try:
        return service.users().messages().list(**params).execute()
    except HttpError as e:
        raise RuntimeError(f"Gmail API error listing messages: {e.reason}")


def get_message_raw(service, message_id: str) -> Tuple[str, bytes]:
    """
    Fetch raw RFC-822 message from Gmail API.
    Returns (decoded_utf8_string, raw_bytes).
    """
    try:
        res = service.users().messages().get(userId="me", id=message_id, format="raw").execute()
        raw_b64 = res.get("raw", "")
        # Add padding if needed
        rem = len(raw_b64) % 4
        if rem > 0:
            raw_b64 += "=" * (4 - rem)
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        return raw_text, raw_bytes
    except HttpError as e:
        raise RuntimeError(f"Gmail API error fetching raw message: {e.reason}")


def _decode_body_data(data_b64: str) -> str:
    """Helper to safely decode base64url encoded message body parts."""
    if not data_b64:
        return ""
    try:
        rem = len(data_b64) % 4
        if rem > 0:
            data_b64 += "=" * (4 - rem)
        decoded_bytes = base64.urlsafe_b64decode(data_b64)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_parts(part: Dict[str, Any], plain_parts: List[str], html_parts: List[str], attachments: List[Dict[str, Any]]) -> None:
    """Recursively traverse MIME parts to extract plain text, HTML, and attachment metadata."""
    mime_type = part.get("mimeType", "")
    filename = part.get("filename", "")
    body_info = part.get("body", {})

    # If it has a filename, it's an attachment
    if filename:
        attachments.append({
            "filename": filename,
            "mimeType": mime_type or "application/octet-stream",
            "size": body_info.get("size", 0),
            "attachmentId": body_info.get("attachmentId", "Not available")
        })

    # Body extraction
    data = body_info.get("data")
    if data:
        decoded_text = _decode_body_data(data)
        if mime_type == "text/plain":
            plain_parts.append(decoded_text)
        elif mime_type == "text/html":
            html_parts.append(decoded_text)

    # Sub-parts recursion
    sub_parts = part.get("parts", [])
    for sub in sub_parts:
        _extract_parts(sub, plain_parts, html_parts, attachments)


def _extract_urls(text: str) -> List[str]:
    """Extract and de-duplicate HTTP/HTTPS URLs from message text."""
    if not text:
        return []
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    found = url_pattern.findall(text)
    # Clean trailing punctuation from URLs
    cleaned = []
    seen = set()
    for u in found:
        u_clean = u.rstrip(".,;:)\"'>")
        if u_clean and u_clean not in seen:
            seen.add(u_clean)
            cleaned.append(u_clean)
    return cleaned


def _parse_authentication_status(auth_results: str, received_spf: str) -> Dict[str, str]:
    """Parse SPF, DKIM, and DMARC status from authentication headers."""
    spf_status = "Not available"
    dkim_status = "Not available"
    dmarc_status = "Not available"

    combined = f"{auth_results} {received_spf}".lower()

    if combined.strip():
        # SPF
        if "spf=pass" in combined or "pass (google.com:" in combined or "received-spf: pass" in combined:
            spf_status = "PASS"
        elif "spf=fail" in combined or "spf=softfail" in combined or "received-spf: fail" in combined:
            spf_status = "FAIL"
        elif "spf=neutral" in combined or "spf=none" in combined:
            spf_status = "NEUTRAL"

        # DKIM
        if "dkim=pass" in combined:
            dkim_status = "PASS"
        elif "dkim=fail" in combined:
            dkim_status = "FAIL"
        elif "dkim=none" in combined or "dkim=neutral" in combined:
            dkim_status = "NONE"

        # DMARC
        if "dmarc=pass" in combined:
            dmarc_status = "PASS"
        elif "dmarc=fail" in combined or "action=reject" in combined or "p=reject" in combined:
            dmarc_status = "REJECT"
        elif "dmarc=none" in combined:
            dmarc_status = "NONE"

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
    }


def parse_message_full(msg_data: Dict[str, Any], raw_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Parse a Gmail message fetched with format='full' into an extensive forensic record.
    Adheres strictly to requirement 8 (never invent missing fields; defaults to 'Not available').
    """
    msg_id = msg_data.get("id", "Not available")
    thread_id = msg_data.get("threadId", "Not available")
    snippet = msg_data.get("snippet", "Not available")
    internal_date_ms = int(msg_data.get("internalDate", 0))

    formatted_date = "Not available"
    if internal_date_ms:
        try:
            dt = datetime.fromtimestamp(internal_date_ms / 1000.0)
            formatted_date = dt.strftime("%b %d, %Y %I:%M %p")
        except Exception:
            formatted_date = "Not available"

    payload = msg_data.get("payload", {})
    mime_type = payload.get("mimeType", "Not available")
    raw_headers = payload.get("headers", [])

    # Index headers (lowercase for case-insensitive lookup)
    headers_dict: Dict[str, str] = {}
    received_hops: List[str] = []

    for h in raw_headers:
        name = h.get("name", "").strip()
        val = h.get("value", "").strip()
        name_lower = name.lower()
        if name_lower == "received":
            received_hops.append(val)
        else:
            headers_dict[name_lower] = val

    # Header fields
    from_header = headers_dict.get("from", "Not available")
    sender_name, sender_email = parseaddr(from_header)
    if not sender_name and sender_email:
        sender_name = sender_email
    elif not sender_name and not sender_email:
        sender_name = from_header
        sender_email = from_header

    to_header = headers_dict.get("to", "Not available")
    cc_header = headers_dict.get("cc", "Not available")
    reply_to_header = headers_dict.get("reply-to", "Not available")
    subject_header = headers_dict.get("subject", "(No Subject)")
    date_header = headers_dict.get("date", formatted_date)
    message_id_header = headers_dict.get("message-id", "Not available")
    return_path_header = headers_dict.get("return-path", "Not available")
    auth_results_header = headers_dict.get("authentication-results", "Not available")
    received_spf_header = headers_dict.get("received-spf", "Not available")

    # Body extraction
    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    # Check root body first
    root_body = payload.get("body", {})
    if root_body.get("data"):
        decoded = _decode_body_data(root_body.get("data", ""))
        if mime_type == "text/plain":
            plain_parts.append(decoded)
        elif mime_type == "text/html":
            html_parts.append(decoded)

    # Check child parts
    for part in payload.get("parts", []):
        _extract_parts(part, plain_parts, html_parts, attachments)

    full_plain_body = "\n\n".join(plain_parts).strip() or "Not available"
    full_html_body = "".join(html_parts).strip() or "Not available"

    # URLs extraction
    urls = _extract_urls(f"{full_plain_body}\n{full_html_body}")

    # Auth Status (SPF, DKIM, DMARC)
    auth_status = _parse_authentication_status(auth_results_header, received_spf_header)

    # Reconstruct authentic RFC-822 text payload for immediate forensic scanner ingestion
    if raw_text:
        reconstructed_rfc822 = raw_text
    else:
        # Build syntactically sound RFC-822 stream using extracted authentic headers
        rfc_lines = []
        if auth_results_header != "Not available":
            rfc_lines.append(f"Authentication-Results: {auth_results_header}")
        elif received_spf_header != "Not available":
            rfc_lines.append(f"Received-SPF: {received_spf_header}")
        for hop in received_hops:
            rfc_lines.append(f"Received: {hop}")
        if return_path_header != "Not available":
            rfc_lines.append(f"Return-Path: {return_path_header}")
        if message_id_header != "Not available":
            rfc_lines.append(f"Message-ID: {message_id_header}")
        rfc_lines.append(f"From: {from_header}")
        if to_header != "Not available":
            rfc_lines.append(f"To: {to_header}")
        if reply_to_header != "Not available":
            rfc_lines.append(f"Reply-To: {reply_to_header}")
        rfc_lines.append(f"Subject: {subject_header}")
        rfc_lines.append(f"Date: {date_header}")
        rfc_lines.append("")
        rfc_lines.append(full_plain_body if full_plain_body != "Not available" else snippet)
        reconstructed_rfc822 = "\n".join(rfc_lines)

    return {
        "id": msg_id,
        "threadId": thread_id,
        "snippet": snippet,
        "formattedDate": formatted_date,
        "mimeType": mime_type,
        "headers": {
            "from": from_header,
            "senderName": sender_name,
            "senderEmail": sender_email,
            "to": to_header,
            "cc": cc_header,
            "replyTo": reply_to_header,
            "subject": subject_header,
            "date": date_header,
            "messageId": message_id_header,
            "returnPath": return_path_header,
            "authenticationResults": auth_results_header,
            "receivedHops": received_hops if received_hops else ["Not available"],
        },
        "authStatus": auth_status,
        "body": {
            "plain": full_plain_body,
            "html": full_html_body,
        },
        "attachments": attachments,
        "urls": urls,
        "reconstructedRaw": reconstructed_rfc822,
    }
