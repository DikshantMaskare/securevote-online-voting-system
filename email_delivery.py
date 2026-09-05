"""Production email delivery for SecureVote using the Gmail API over HTTPS."""

import base64
import os
from email.message import EmailMessage

import requests


TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"


def _get_access_token(client_id, client_secret, refresh_token):
    response = requests.post(
        TOKEN_URL,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def send_otp_email(
    to_email,
    otp,
    purpose="verification",
):
    """Send a SecureVote OTP through the Gmail API.

    Returns:
        True: Gmail accepted the message.
        False: development fallback is allowed and the OTP was printed locally.
        None: delivery is unavailable or failed and production must fail closed.
    """

    client_id = os.environ.get("GMAIL_CLIENT_ID")
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET")
    refresh_token = os.environ.get("GMAIL_REFRESH_TOKEN")
    sender_email = os.environ.get("GMAIL_SENDER_EMAIL")
    allow_dev_otp = os.environ.get("ALLOW_DEV_OTP", "0") == "1"

    if not all((client_id, client_secret, refresh_token, sender_email)):
        if allow_dev_otp:
            print(
                f"[DEV OTP] {purpose} code "
                f"for {to_email}: {otp}"
            )
            return False

        print("[OTP ERROR] Gmail API is not configured.")
        return None

    try:
        access_token = _get_access_token(
            client_id,
            client_secret,
            refresh_token,
        )

        message = EmailMessage()
        message["To"] = to_email
        message["From"] = f"SecureVote <{sender_email}>"
        message["Subject"] = f"Your SecureVote OTP for {purpose}"
        message.set_content(
            f"Your SecureVote OTP is {otp}. "
            "It expires in 5 minutes. "
            "If you did not request this code, ignore this email."
        )

        raw = base64.urlsafe_b64encode(
            message.as_bytes()
        ).decode("ascii")

        response = requests.post(
            GMAIL_SEND_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={"raw": raw},
            timeout=15,
        )
        response.raise_for_status()
        return True

    except Exception as exc:
        # Do not print the OTP, OAuth secrets, refresh token, or access token.
        print(f"[GMAIL API ERROR] {type(exc).__name__}: {exc}")

        if allow_dev_otp:
            print(
                f"[DEV OTP] {purpose} code "
                f"for {to_email}: {otp}"
            )
            return False

        return None
