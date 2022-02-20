import os
import ssl
import codecs
from email.mime.text import MIMEText
import smtplib
import yenot.backend.api as api

app = api.get_global_app()


def communicate_2fa(target, session_id, pin6):
    pin6s = f"{pin6[:3]} {pin6[3:]}"

    shortbody = f"Your one-time PIN is {pin6s}"
    longbody = shortbody
    subject = "Login Verification"

    seg = codecs.encode(session_id.encode("ascii"), "hex").decode("ascii")

    filebase = f"authpin-{seg}"
    _internal_communicate(target, filebase, pin6, subject, longbody, shortbody)


def communicate_invite(target, userid, request, token):
    if target.addr_type != "email":
        raise RuntimeError(
            "Can only accept an invite from an e-mail with a complicated URL."
        )

    base = request.environ["YENOT_BASE_URL"]
    url = f"{base}/api/user/{userid}/accept-invite?token={token}"

    shortbody = None
    longbody = f"You are invited to join this awesome organization.  Click {url} to complete your account sign-up & set up 2FA devices."
    subject = "Account Invite"

    filebase = f"acceptinvite--{userid}"
    _internal_communicate(target, filebase, token, subject, longbody, shortbody)


def communicate_verify(target, userid, request, addrid, confirmation):
    base = request.environ["YENOT_BASE_URL"]
    url = f"{base}/api/user/{userid}/address/{addrid}/verify"

    shortbody = f"Verify this phone number by entering {confirmation}"
    longbody = f"Verify this e-mail address by clicking {url} or entering verification code {confirmation}"
    subject = "Address Verification"

    filebase = f"addrverify--{userid}--{addrid}"
    _internal_communicate(target, filebase, confirmation, subject, longbody, shortbody)


def _internal_communicate(target, filebase, value, subject, longbody, shortbody):
    if os.getenv("YENOT_DEBUG") and os.getenv("YENOT_2FA_DIR"):
        dirname = os.environ["YENOT_2FA_DIR"]
        fname = os.path.join(dirname, filebase)
        # TODO:  figure out how to test subject, shortbody, longbody
        with open(fname, "w") as f:
            f.write(value)

        # NOTE:  debug write-to-file supersedes real 2fa notifications for
        # test-run efficiency
        return

    if target.addr_type == "phone":
        send_sms(target.address, body=shortbody)

    if target.addr_type == "email":
        send_email(target.address, subject=subject, content=longbody)


def send_sms(phone, body):
    from twilio.rest import Client

    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    src_phone = os.getenv("TWILIO_SRC_PHONE")

    client = Client(account_sid, auth_token)
    client.messages.create(to=phone, from_=src_phone, body=body)


def send_email(to_, subject, content):
    server = smtplib.SMTP(os.getenv("SMTP_SERVER"), port=int(os.getenv("SMTP_PORT")))
    context = ssl.create_default_context()
    server.starttls(context=context)
    server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))

    msg = MIMEText(content)
    msg["From"] = os.getenv("SMTP_FROM")
    msg["Subject"] = subject
    server.sendmail(os.getenv("SMTP_FROM"), to_, msg.as_string())
