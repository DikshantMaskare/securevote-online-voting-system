"""WSGI entry point for production deployments.

Imports the existing SecureVote Flask application and replaces only its
OTP delivery function with the Resend HTTPS implementation. OTP generation,
hashing, expiry, cooldown, attempt limits, and fail-closed behavior remain in
app.py.
"""

import app as securevote
from email_delivery import send_otp_email

securevote.send_otp_email = send_otp_email
app = securevote.app
