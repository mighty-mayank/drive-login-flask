# server.py
import os
import time
import json
import threading
from urllib.parse import urlencode

import requests
from flask import Flask, request, render_template, redirect, jsonify

#
# Simple Drive-login compatible server (show-code flow)
#
# Configure via environment variables:
#  - CLIENT_ID
#  - CLIENT_SECRET
#  - BASE_URL  (e.g. https://yourapp.onrender.com)  <-- must be https and match Google console redirect URI
#  - SECRET_KEY (optional, for Flask sessions)
#
# Endpoints:
#  - GET /                 -> landing + "Sign in with Google" button + form to paste Kodi code
#  - GET /login            -> redirect to Google OAuth consent
#  - GET /oauth2callback   -> Google redirects here with ?code=... ; server exchanges for tokens and shows form to enter Kodi code
#  - POST /bind            -> form submits Kodi code -> server stores mapping code -> token info
#  - GET /token?code=ABC   -> Kodi polls this endpoint; returns JSON {access_token, refresh_token, expires_in, obtained_at}
#  - POST /register        -> Kodi sends code, server returns URL to open
#  - GET /status/<code>    -> Kodi polls login status
#  - GET /ping             -> health check
#

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "change-me-in-production")

CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "")  # e.g. https://mydrive-login.onrender.com

if not CLIENT_ID or not CLIENT_SECRET or not BASE_URL:
    print("WARNING: CLIENT_ID, CLIENT_SECRET, BASE_URL must be set as environment variables.")

# in-memory store: code -> {access_token, refresh_token, expires_at, obtained_at, raw}
STORE = {}
STORE_LOCK = threading.Lock()
CODE_TTL_SECONDS = 10 * 60  # 10 minutes

GOOGLE_OAUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive.metadata.readonly https://www.googleapis.com/auth/photoslibrary.readonly"

def cleanup_store():
    """Remove expired codes periodically."""
    while True:
        with STORE_LOCK:
            now = time.time()
            keys = list(STORE.keys())
            for k in keys:
                if STORE[k].get("expires_at", 0) < now:
                    del STORE[k]
        time.sleep(60)

# Start cleanup thread
t = threading.Thread(target=cleanup_store, daemon=True)
t.start()

# --- MAIN PAGES ---

@app.route("/")
def index():
    kodi_code = request.args.get("kodi_code", "").strip().upper()
    return render_template("index.html", base_url=BASE_URL, kodi_code=kodi_code)

@app.route("/login")
def login():
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPE,
        "redirect_uri": BASE_URL.rstrip("/") + "/oauth2callback",
        "access_type": "offline",
        "prompt": "consent",
    }
    url = GOOGLE_OAUTH_URL + "?" + urlencode(params)
    return redirect(url)

@app.route("/oauth2callback")
def oauth2callback():
    code = request.args.get("code")
    if not code:
        return "Missing code from Google", 400

    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": BASE_URL.rstrip("/") + "/oauth2callback",
        "grant_type": "authorization_code"
    }
    r = requests.post(GOOGLE_TOKEN_URL, data=data)
    if r.status_code != 200:
        return f"Token exchange failed: {r.status_code} {r.text}", 500
    token_info = r.json()
    return render_template("done.html", token_info=json.dumps(token_info), token_json=json.dumps(token_info))

@app.route("/bind", methods=["POST"])
def bind():
    kodi_code = request.form.get("kodi_code", "").strip().upper()
    token_info = request.form.get("token_info", "")
    if not kodi_code or not token_info:
        return "Missing code or token", 400

    try:
        token_info = json.loads(token_info)
    except Exception:
        return "Invalid token JSON", 400

    now = time.time()
    with STORE_LOCK:
        STORE[kodi_code] = {
            "access_token": token_info.get("access_token"),
            "refresh_token": token_info.get("refresh_token"),
            "expires_at": now + int(token_info.get("expires_in", 3600)),
            "obtained_at": now,
            "raw": token_info
        }
    return render_template("bind_success.html", kodi_code=kodi_code)

@app.route("/token")
def token():
    code = request.args.get("code", "").strip().upper()
    if not code:
        return jsonify({"error":"missing_code"}), 400

    with STORE_LOCK:
        rec = STORE.get(code)
    if not rec:
        return jsonify({"available": False}), 404

    now = time.time()
    if rec.get("expires_at", 0) <= now + 30 and rec.get("refresh_token"):
        refresh_payload = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": rec.get("refresh_token"),
            "grant_type": "refresh_token"
        }
        rr = requests.post(GOOGLE_TOKEN_URL, data=refresh_payload)
        if rr.status_code == 200:
            newtokens = rr.json()
            rec["access_token"] = newtokens.get("access_token")
            rec["expires_at"] = now + int(newtokens.get("expires_in", 3600))
            rec["obtained_at"] = now
            if newtokens.get("refresh_token"):
                rec["refresh_token"] = newtokens.get("refresh_token")
            rec["raw"].update(newtokens)
            with STORE_LOCK:
                STORE[code] = rec

    out = {
        "access_token": rec.get("access_token"),
        "refresh_token": rec.get("refresh_token"),
        "expires_in": int(rec.get("expires_at", now) - now),
        "obtained_at": rec.get("obtained_at"),
    }
    return jsonify(out)

# --- HEALTH CHECK ---
@app.route("/ping")
def ping():
    return "pong", 200

# --- KODI LOGIN COMPATIBILITY ---
@app.route("/register", methods=["POST"])
def kodi_register():
    data = request.get_json(force=True)
    kodi_code = data.get("code", "").strip().upper()
    if not kodi_code:
        return jsonify({"error": "missing_code"}), 400

    with STORE_LOCK:
        if kodi_code not in STORE:
            STORE[kodi_code] = {
                "access_token": None,
                "refresh_token": None,
                "expires_at": 0,
                "obtained_at": 0,
                "raw": None
            }

    return jsonify({
        "status": "pending",
        "url": f"{BASE_URL}/?kodi_code={kodi_code}"
    })

@app.route("/status/<code>")
def status(code):
    code = code.strip().upper()
    with STORE_LOCK:
        rec = STORE.get(code)
    if not rec:
        return jsonify({"status": "pending"}), 200

    if rec.get("access_token"):
        return jsonify({
            "status": "success",
            "access_token": rec.get("access_token"),
            "refresh_token": rec.get("refresh_token"),
            "expires_in": int(rec.get("expires_at", time.time()) - time.time()),
            "obtained_at": rec.get("obtained_at")
        }), 200
    else:
        return jsonify({"status": "pending"}), 200

# --- ENDPOINT OK ---
@app.route("/ok")
def ok():
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
