import os
from base64 import b32encode, b64encode
from io import BytesIO

import pyotp
import base64
import frappe
from datetime import timedelta
import frappe.defaults
from frappe import _
from frappe.permissions import ALL_USER_ROLE
from frappe.utils import cint, get_datetime, get_url, time_diff_in_seconds
from frappe.utils.background_jobs import enqueue
from frappe.utils.password import decrypt, encrypt
import random
import json
import os
import secrets
from email.utils import formataddr
from email.message import EmailMessage
import smtplib
import ipaddress
import ssl
import string
import urllib.parse
import re
import geoip2.database
import frappe
from frappe.utils import cint
from mimetypes import guess_type
from frappe.utils.image import optimize_image
from frappe import _, is_whitelisted, ping
from erpnext.accounts.utils import get_balance_on, get_fiscal_year
from frappe.utils.response import Response
import google.auth.transport.requests
from google.oauth2 import service_account
from frappe.utils import now_datetime
from frappe.utils.data import sha256_hash
from frappe.core.doctype.user.user import User
from frappe.core.doctype.user.user import update_password
from frappe.utils.password import update_password
from frappe.utils import get_url
import pyotp
import requests
from werkzeug.wrappers import Response
import firebase_admin
from firebase_admin import credentials, exceptions, messaging
from pyotp import TOTP
from frappe import _


PARENT_FOR_DEFAULTS = "__2fa"
OAUTH_CLIENT = "OAuth Client"
OAUTH_TOKEN_URL = "/api/method/frappe.integrations.oauth2.get_token"
FIELD_NAME_AS_ID = "name as id"
FULL_NAME_ALIAS = "full_name as full_name"
BACKEND_SERVER_SETTINGS = "Backend Server Settings"
USER_NOT_FOUND_MESSAGE = "User not found"
NAME_AS_EMAIL = "name as email"
INVALID_SECURITY_PARAMETERS = "Security Parameters are not valid"
APPLICATION_JSON = "application/json"
PARENT_FOR_DEFAULTS = "Parent Defaults"
INVALID_SECURITY_PARAMETERS = "Invalid security parameters"
OAUTH_TOKEN_URL = "/api/method/frappe.integrations.oauth2.get_token"
FIELD_NAME_AS_ID = "name"
FULL_NAME_ALIAS = "full_name"


def send_email_oci(recipient, subject, otp):
    """Send an email to the recipient with subject."""
    sender = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "sender")
    sender_name = frappe.db.get_single_value(
                BACKEND_SERVER_SETTINGS, "sender_name"
                )
    user_smtp = frappe.db.get_single_value(
        BACKEND_SERVER_SETTINGS, "user_smtp"
        )
    password_smtp = frappe.db.get_single_value(
        BACKEND_SERVER_SETTINGS, "password_smtp"
        )
    host = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "host")
    port = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "port")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, sender))
    msg["To"] = recipient
    msg.set_content(otp, subtype="html")
    try:
        server = smtplib.SMTP(host, port)
        server.ehlo()
        context = ssl.create_default_context()
        server.starttls(context=context)
        server.ehlo()
        server.login(user_smtp, password_smtp)
        server.sendmail(sender, recipient, msg.as_string())
        server.close()
        return "Email successfully sent!"
    except Exception as e:
        return f"Error: {e}"


@frappe.whitelist(allow_guest=True)
def authenticate_for_2factor1(user):
    """Authenticate two-factor authentication for enabled user before login."""
    if frappe.form_dict.get("otp"):
        return
    otp_secret = get_otpsecret_for_(user)
    token = int(TOTP(otp_secret).now())
    return token


def get_default(key):
    return frappe.db.get_default(key, parent=PARENT_FOR_DEFAULTS)


def set_default(key, value):
    frappe.db.set_default(key, value, parent=PARENT_FOR_DEFAULTS)


def clear_default(key):
    frappe.defaults.clear_default(key, parent=PARENT_FOR_DEFAULTS)


@frappe.whitelist(allow_guest=True)
def get_otpsecret_for_(user):
    otp_secret = get_default(user + "_otpsecret")
    if otp_secret:

        return decrypt(otp_secret)

    # Generate a new OTP secret if it doesn't exist
    otp_secret = b32encode(os.urandom(10)).decode("utf-8")
    set_default(
        user + "_otpsecret", encrypt(otp_secret)
    )  # Storing the encrypted OTP secret
    frappe.db.commit()
    return otp_secret


# using frappe cache
@frappe.whitelist(allow_guest=True)
def validate_otp_to_generate_user_token(user, user_otp):
    try:
        # Retrieve OTP from cache
        otp_data = frappe.cache().get_value(f"otp_{user}")
        frappe.log_error(message=str(otp_data), title="OTP Cache Debug")
        customer_data = frappe.get_all(
            "Customer",
            fields=[
                "customer_name as id",
                "customer_name as  full_name",
                "mobile as mobile",
                # "name as email",
                # "custom_qid as qid",
            ],
            filters={"name": ["like", user]},
        )
        # return customer_data
        if not otp_data:
            return Response(
                    json.dumps({
                        "success": False,
                        "message": "OTP expired or not found"
                    }),
                    status=400,
                    mimetype="application/json",
                )

        # Check expiration with a buffer time
        if frappe.utils.now_datetime() > otp_data["expires_at"]:
            frappe.cache().delete_value(f"otp_{user}")
            return {"success": False, "message": "OTP expired"}

        # Check if OTP matches
        if otp_data["otp"] == user_otp:
            # frappe.cache().delete_value(f"otp_{user}")
            refresh_token = otp_data["token"].get("refresh_token", None)
            response = Response(
                json.dumps(
                    {
                        "success": True,
                        "message": "OTP validated successfully",
                        "token": otp_data["token"],
                        "user": customer_data,
                    }
                ),
                status=200,
                mimetype="application/json",
            )
            if refresh_token:
                response.set_cookie(
                    "refresh_token",
                    refresh_token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    max_age=30 * 24 * 60 * 60,  # Expiry in 30 days
                )

            return response
        else:
            # return {"success": False, "message": "Invalid OTP"}
            return Response(
                json.dumps({"message": "Invalid OTP"}),
                status=400,
                mimetype="application/json",
            )
    except Exception as e:
        frappe.log_error(message=str(e), title="OTP Validation Error")
        # return {"success": False, "message": "Error during OTP validation"}
        return Response(
            json.dumps({"message": "Error during OTP validation"}),
            status=401,
            mimetype="application/json",
        )


# using frappe cache
@frappe.whitelist(allow_guest=True)
def generate_token_encrypt_for_user_2fa(encrypted_key):
    """Generate a user token using an encrypted key."""
    try:
        # Decrypt the provided key
        try:
            _, decrypted_key = decrypt_2fa_key(encrypted_key)
            api_key, api_secret, app_key = decrypted_key.split("::")

        except ValueError:
            return Response(
                json.dumps({"message": "2FA token expired or invalid"}),
                status=401,
                mimetype="application/json",
            )

        # Decode the application key
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception:
            return Response(
                json.dumps({"message": INVALID_SECURITY_PARAMETERS}),
                status=401,
                mimetype="application/json",
            )
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if client_id_value is None:
            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS, "user_count": 0}
                    ),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        client_id = client_id_value
        client_secret = client_secret_value
        url = frappe.local.conf.host_name + OAUTH_TOKEN_URL
        payload = {
            "username": api_key,
            "password": api_secret,
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        files = []
        headers = {"Content-Type": APPLICATION_JSON}
        response = requests.request("POST", url, data=payload, files=files)
        # qid = frappe.get_all(
        #     "Customer",
        #     fields=[
        #         "email as id",
        #         "full_name as name",
        #         "email as email",
        #         "mobile",
        #         "qid",
        #         "custom_customer_company as company",
        #     ],
        #     filters={"email": ["like", api_key]},
        # )
        # return qid
        result_data = []
        if response.status_code == 200:
            try:
                result_data = response.json()
            except json.JSONDecodeError as json_error:
                return Response(
                    json.dumps(
                        {"message": "Invalid JSON response",
                         "error": str(json_error)
                         }
                    ),
                    status=500,
                    mimetype=APPLICATION_JSON,
                )

        existing_otp = frappe.cache().get_value(f"otp_{api_key}")
        if existing_otp and frappe.utils.now_datetime() < existing_otp["expires_at"]:
            return {
                "success": False,
                "message": "An OTP already exists",
            }

        # Generate OTP
        otp = authenticate_for_2factor1(api_key)
        otp = str(otp)
        # Validate OTP length
        if len(otp) != 6 or not otp.isdigit():
            return Response(
                json.dumps(
                    {"message": "Invalid OTP generated. Please try again."}
                    ),
                status=400,
                mimetype="application/json",
            )
        expires = frappe.utils.now_datetime() + timedelta(seconds=60)
        frappe.cache().set_value(
            f"otp_{api_key}",
            {
                "otp": otp,
                "expires_at":expires,
                # "user": api_key,
                "token": result_data,
                # "user": qid[0] if qid else {},
            },
        )
        # Send OTP via email
        try:
            email_template = frappe.get_doc("Email Template", "gauth erpgulf")
            message = email_template.response_html
            message = message.replace("xxxxxx", otp)
            updated_html_content = message.replace("John Deo", api_key)
            subject = "Your OTP Code"
            send_email_oci(api_key, subject, updated_html_content)
        except Exception as e:
            frappe.log_error(str(e), "Email Template or Sending Error")
            return Response(
                json.dumps(
                    {"message": "Email template not found or sending failed"}
                    ),
                status=500,
                mimetype="application/json",
            )
        # Return OTP required response
        return Response(
            json.dumps({"data": "OTP verification is required"}),
            status=200,
            mimetype="application/json",
        )

        return response
    except Exception as e:
        frappe.log_error(message=str(e), title="2FA Token Generation Error")


@frappe.whitelist(allow_guest=False)
def xor_encrypt_decrypt(text, key):
    """Encrypt or decrypt text using XOR operation."""
    return "".join(
        chr(ord(c) ^ ord(k)) for c, k in zip(text, key * (len(text) // len(key) + 1))
    )


@frappe.whitelist(allow_guest=True)
def generate_totp():
    """Generate TOTP token using 2FA secret."""
    secret = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "2fa_secret_key")
    totp = pyotp.TOTP(secret, interval=60)
    return totp.now()


@frappe.whitelist(allow_guest=True)
def decrypt_2fa_key(encrypted_key):
    """This function used for decrypting the 2FA encrypted Key"""
    current_totp = generate_totp()
    encrypted = base64.b64decode(encrypted_key).decode()
    return current_totp, xor_encrypt_decrypt(encrypted, current_totp)


@frappe.whitelist(allow_guest=True)
def get_oauth_client(app_key):
    """Fetch client_id and client_secret for an OAuth client."""
    client_id, client_secret, _ = frappe.db.get_value(
        OAUTH_CLIENT,
        {"app_name": app_key},
        ["client_id", "client_secret", "user"],
    )
    if not client_id:
        raise frappe.ValidationError(_(INVALID_SECURITY_PARAMETERS))
    return client_id, client_secret
