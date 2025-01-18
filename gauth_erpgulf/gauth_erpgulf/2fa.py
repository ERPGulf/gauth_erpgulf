import os
import random
import json
import secrets
import string
import re
import base64
import pyotp
from base64 import b32encode, b64encode
from io import BytesIO
from datetime import timedelta
from email.utils import formataddr
from email.message import EmailMessage
import smtplib
import ssl
import ipaddress
import urllib.parse
import requests
from werkzeug.wrappers import Response
import geoip2.database
import firebase_admin
from firebase_admin import credentials, exceptions, messaging
from pyotp import TOTP
from google.oauth2 import service_account
import google.auth.transport.requests

# Frappe and ERPNext imports
import frappe
import frappe.defaults
from frappe import _, is_whitelisted, ping
from frappe.permissions import ALL_USER_ROLE
from frappe.utils import (
    cint,
    get_datetime,
    get_url,
    time_diff_in_seconds,
    now_datetime,
    sha256_hash,
)
from frappe.utils.background_jobs import enqueue
from frappe.utils.image import optimize_image
from frappe.utils.password import encrypt, decrypt, update_password
from frappe.utils.response import Response
from frappe.core.doctype.user.user import User
from erpnext.accounts.utils import get_balance_on, get_fiscal_year

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
TWO_FA_TOKEN_EXPIRED = "2FA token expired"
STATUS_500 = 500
STATUS_200 = 200
MOBILE_NO_ALIAS = "mobile_no as mobile_no"


def generate_error_response(message, error, status=STATUS_500):
    return Response(
        json.dumps({"message": message, "error": error, "user_count": 0}),
        status=status,
        mimetype=APPLICATION_JSON,
    )


# API for encrypted user token
@frappe.whitelist(allow_guest=False)
def test_generate_token_encrypt_for_user_2fa(encrypted_key):
    """to generate a usertoken using encrypted key"""
    try:
        # Step 1: Decrypt the encrypted key
        try:
            _, decrypted_key = decrypt_2fa_key(encrypted_key)
            api_key, api_secret, app_key = decrypted_key.split("::")
        except ValueError as ve:
            return generate_error_response(
                message=TWO_FA_TOKEN_EXPIRED,
                error="Decryption failed.Token expired.",
                status=401,
            )

        # Step 2: Decode the app_key
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except (ValueError, base64.binascii.Error):
            return generate_error_response(
                message=INVALID_SECURITY_PARAMETERS,
                error="Invalid app_key format.",
                status=401,
            )

        # Step 3: Get OAuth client credentials
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if not client_id_value:
            return generate_error_response(
                message=INVALID_SECURITY_PARAMETERS,
                error="Invalid client ID or secret.",
                status=401,
            )

        # Step 4: Prepare payload and send token request
        url = frappe.local.conf.host_name + OAUTH_TOKEN_URL
        payload = {
            "username": api_key,
            "password": api_secret,
            "grant_type": "password",
            "client_id": client_id_value,
            "client_secret": client_secret_value,
        }
        response = requests.post(url, data=payload, timeout=10)

        # Step 5: Handle response and fetch user details
        if response.status_code == STATUS_200:
            result_data = response.json()
            result_data["refresh_token"] = "XXXXXXX"
            qid = frappe.get_all(
                "User",
                fields=[FIELD_NAME_AS_ID, FULL_NAME_ALIAS, MOBILE_NO_ALIAS],
                filters={"name": ["like", api_key]},
            )
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return generate_success_response(result, status=STATUS_200)
        else:
            # Handle non-200 status codes
            return generate_error_response(
                message="Failed to generate token.",
                error=response.text,
                status=response.status_code,
            )

    except ValueError as ve:
        return generate_error_response(
            message="An unexpected error occurred.",
            error=str(ve),
            status=STATUS_500
        )
    except Exception as e:
        return generate_error_response(
            message="A general error occurred.", error=str(e), status=STATUS_500
        )

def generate_success_response(data, status=STATUS_200):
    return Response(
        json.dumps({"data": data}),
        status=status,
        mimetype=APPLICATION_JSON,
    )

def send_email_oci(recipient, subject, otp):
    """Send an email to the recipient with subject."""
    sender = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "sender")
    sender_name = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "sender_name")
    user_smtp = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "user_smtp")
    password_smtp = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "password_smtp")
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

def generate_totp_without_leading_zero(totp):
    """Generate TOTP without leading zeros."""
    while True:
        token = totp.now()  # Generate the TOTP
        if token[0] != "0":  # Check if the first digit is not zero
            return token


@frappe.whitelist(allow_guest=True)
def authenticate_for_2factor(user):
    """Authenticate two-factor authentication for enabled user before login."""
    if frappe.form_dict.get("otp"):
        return

    otp_secret = get_otpsecret_for_(user)
    totp = TOTP(otp_secret, digits=6)

    # Use the function to generate an OTP without leading zeros
    otp = generate_totp_without_leading_zero(totp)

    return otp


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
        # Correcting the `decrypt` call to remove the unexpected 'key' argument
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
                "customer_name as  name",
                "customer_name as email",
                "mobile_no as mobile",
            ],
            filters={"customer_name": ["like", user]},
        )
        if not otp_data:
            return Response(
                json.dumps({"success": False, "message": "OTP expired or not found"}),
                status=400,
                mimetype="application/json",
            )

        # Check expiration with a buffer time
        if frappe.utils.now_datetime() > otp_data["expires_at"]:
            frappe.cache().delete_value(f"otp_{user}")
            return {"success": False, "message": "OTP expired"}

        # Check if OTP matches
        if otp_data["otp"] ==user_otp:
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
#login api
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
                json.dumps({"message": INVALID_SECURITY_PARAMETERS, "user_count": 0}),
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
        qid = frappe.get_all(
            "Customer",
            fields=[
                "customer_name as name",
                "customer_name as email",
                "mobile_no as mobile",
            ],
            filters={"customer_name": ["like", api_key]},
        )

        result_data = []
        if response.status_code == 200:
            try:
                result_data = response.json()
            except json.JSONDecodeError as json_error:
                return Response(
                    json.dumps(
                        {"message": "Invalid JSON response", "error": str(json_error)}
                    ),
                    status=500,
                    mimetype=APPLICATION_JSON,
                )

        existing_otp = frappe.cache().get_value(f"otp_{api_key}")
        if existing_otp and frappe.utils.now_datetime() < existing_otp["expires_at"]:
            return {
                "success": False,
                "message": "An OTP already exists. Please validate the current OTP.",
            }

        # Generate OTP without leading zeros
        otp = authenticate_for_2factor(api_key)
        frappe.cache().set_value(
            f"otp_{api_key}",
            {
                "otp": otp,
                "expires_at": frappe.utils.now_datetime() + timedelta(seconds=600),
                "token": result_data,
                "user": qid[0] if qid else {},
            },
        )

        # Send OTP via email
        try:
            email_template = frappe.get_doc("Email Template", "gauth erpgulf")
            message = email_template.response_html
            message = message.format(otp=otp)
            updated_html_content = message.replace("John Deo", api_key)
            subject = "Your OTP Code"
            send_email_oci(api_key, subject, updated_html_content)
        except Exception as e:
            frappe.log_error(str(e), "Email Template or Sending Error")
            return Response(
                json.dumps({"message": "Email template not found or sending failed"}),
                status=500,
                mimetype=APPLICATION_JSON,
            )

        # Return OTP required response
        return Response(
            json.dumps({"data": "OTP verification is required"}),
            status=200,
            mimetype="application/json",
        )

    except Exception as e:
        frappe.log_error(message=str(e), title="2FA Token Generation Error")



@frappe.whitelist(allow_guest=True)
def resend_otp(user):
    """
    Resend the OTP to the user's email.
    """
    try:
        # Check if an OTP exists in the cache
        otp_data = frappe.cache().get_value(f"otp_{user}")
        otp_secret = get_otpsecret_for_(user)
        totp = TOTP(otp_secret, digits=6)

        if otp_data and frappe.utils.now_datetime() < otp_data["expires_at"]:
            # Use existing OTP if it's still valid
            otp = otp_data["otp"]
        else:
            # Generate a new OTP if the existing one is expired or missing
            otp = generate_totp_without_leading_zero(totp)
            otp_data = {
                "otp": otp,
                "expires_at": frappe.utils.now_datetime() + timedelta(seconds=600),
            }
            frappe.cache().set_value(f"otp_{user}", otp_data)

        # Get user email
        customer_data = frappe.get_all(
            "Customer",
            fields=["customer_name as email"],
            filters={"customer_name": ["like", user]},
        )
        if not customer_data or "email" not in customer_data[0]:
            return Response(
                json.dumps({"success": False, "message": "User email not found"}),
                status=400,
                mimetype="application/json",
            )

        user_email = customer_data[0]["email"]

        # Resend the OTP via email
        try:
            email_template = frappe.get_doc("Email Template", "gauth erpgulf")
            message = email_template.response_html
            message = message.format(otp=otp)
            updated_html_content = message.replace("John Deo",user)
            subject = "Your OTP Code (Resent)"
            send_email_oci(user_email, subject, updated_html_content)
        except Exception as e:
            frappe.log_error(str(e), "Email Template or Sending Error")
            return Response(
                json.dumps({"message": "Email template not found or sending failed"}),
                status=500,
                mimetype="application/json",
            )

        return Response(
            json.dumps({"success": True, "message": "OTP resent successfully"}),
            status=200,
            mimetype="application/json",
        )

    except Exception as e:
        frappe.log_error(message=str(e), title="Resend OTP Error")
        return Response(
            json.dumps({"message": "Failed to resend OTP", "error": str(e)}),
            status=500,
            mimetype="application/json",
        )




@frappe.whitelist(allow_guest=False)
def xor_encrypt_decrypt(text, key):
    """Encrypt or decrypt text using XOR operation."""
    return "".join(
        chr(ord(c) ^ ord(k)) for c, k in zip(text, key * ((len(text) // len(key)) + 1))
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


@frappe.whitelist(allow_guest=True)
def test(api_key):
    qid = frappe.get_all(
        "User",
        fields=["name", "email", "mobile_no"],
        filters={"username": ["like", api_key]},
    )
    return qid
