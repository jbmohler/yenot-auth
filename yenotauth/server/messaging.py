import os
import ssl
from email.mime.text import MIMEText
import smtplib
import yenot.backend.api as api

app = api.get_global_app()


def communicate_2fa(target, session_id, pin6):
    if os.getenv("YENOT_DEBUG") and os.getenv("YENOT_2FA_DIR"):
        import codecs

        dirname = os.environ["YENOT_2FA_DIR"]
        seg = codecs.encode(session_id.encode("ascii"), "hex").decode("ascii")
        fname = os.path.join(dirname, f"authpin-{seg}")
        with open(fname, "w") as f:
            f.write(pin6)

        # NOTE:  debug write-to-file supersedes real 2fa notifications for
        # test-run efficiency
        return

    if target.addr_type == "phone":
        pin6s = f"{pin6[:3]} {pin6[3:]}"
        send_sms(target.address, body=f"Your one-time PIN is {pin6s}")

    if target.addr_type == "email":
        pin6s = f"{pin6[:3]} {pin6[3:]}"
        send_sms(
            target.address,
            subject="Login Verification",
            content=f"Your one-time PIN is {pin6s}",
        )


def send_sms(phone, body):
    from twilio.rest import Client

    # credentials sourced from commandline
    # TODO:  consider whether should just be from env
    account_sid = app.config["twilio"].account_sid
    auth_token = app.config["twilio"].auth_token
    src_phone = app.config["twilio"].src_phone

    client = Client(account_sid, auth_token)
    client.messages.create(to=phone, from_=src_phone, body=body)


def send_mail(to_, subject, content):
    server = smtplib.SMTP(os.getenv("SMTP_SERVER"), port=int(os.getenv("SMTP_PORT")))
    context = ssl.create_default_context()
    server.starttls(context=context)
    server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))

    msg = MIMEText(content)
    msg["From"] = os.getenv("SMTP_FROM")
    msg["Subject"] = subject
    server.sendmail(os.getenv("SMTP_FROM"), to_, msg.as_string())
