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
)
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
# Load environment variables from .env if present
load_dotenv()
# Render & cloud platforms terminate SSL at their reverse proxy.
# Enable INSECURE_TRANSPORT for oauthlib so it does not reject proxy-forwarded HTTP headers.
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
# Relax scope matching for Google OAuth
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
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
