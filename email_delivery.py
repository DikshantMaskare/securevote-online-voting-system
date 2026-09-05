"""Production email delivery for SecureVote using the Resend HTTPS API."""

import os

import resend


def send_otp_email(
    to_email,
    otp,
    purpose="verification",
):
    """Send a SecureVote OTP through Resend.

    Returns:
        True: email accepted by Resend.
        False: development fallback is allowed and the OTP was printed locally.
        None: delivery is unavailable or failed and production must fail closed.
    """

    api_key = os.environ.get("RESEND_API_KEY")
    from_email = os.environ.get("OTP_FROM_EMAIL")
    allow_dev_otp = os.environ.get("ALLOW_DEV_OTP", "0") == "1"

    if not api_key or not from_email:
        if allow_dev_otp:
            print(
                f"[DEV OTP] {purpose} code "
                f"for {to_email}: {otp}"
            )
            return False

        print("[OTP ERROR] Resend is not configured.")
        return None

    try:
        resend.api_key = api_key

        resend.Emails.send(
            {
                "from": from_email,
                "to": [to_email],
                "subject": f"Your SecureVote OTP for {purpose}",
                "text": (
                    f"Your SecureVote OTP is {otp}. "
                    "It expires in 5 minutes. "
                    "If you did not request this code, ignore this email."
                ),
            }
        )

        return True

    except Exception as exc:
        # Log the provider's rejection reason for diagnosis. This does not
        # print the API key or OTP.
        print(f"[RESEND ERROR] {type(exc).__name__}: {exc}")

        if allow_dev_otp:
            print(
                f"[DEV OTP] {purpose} code "
                f"for {to_email}: {otp}"
            )
            return False

        return None
