import os
import random
import json
import secrets
import string
import re
import base64
import frappe.utils
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
from gauth_erpgulf.gauth_erpgulf.backend_server import xor_encrypt_decrypt
from frappe.utils.background_jobs import enqueue
from frappe.utils.image import optimize_image
from frappe.utils.password import encrypt, decrypt, update_password
from frappe.utils.response import Response
from frappe.core.doctype.user.user import User
from erpnext.accounts.utils import get_balance_on, get_fiscal_year
from frappe.utils.password import check_password as _check_password


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
CUSTOMER_NAME_AS_EMAIL="customer_name as email"


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
            message="An unexpected error occurred.", error=str(ve), status=STATUS_500
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
        return decrypt(otp_secret)
    otp_secret = b32encode(os.urandom(10)).decode("utf-8")
    set_default(user + "_otpsecret", encrypt(otp_secret))
    frappe.db.commit()
    return otp_secret


# using frappe cache
@frappe.whitelist(allow_guest=True)
def validate_otp_to_generate_user_token(user, user_otp):
    try:
        user = frappe.get_value("User", {"name": user}, "name")
        if not user:
            return Response(
                json.dumps({"success": False, "message": "User not found"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )
        otp_data = frappe.cache().get_value(f"otp_{user}")
        customer_data = frappe.get_all(
            "Customer",
            fields=[
                "customer_name as  name",
                CUSTOMER_NAME_AS_EMAIL,
                "mobile_no as mobile",
            ],
            filters={"customer_name": ["like", user]},
        )
        if not otp_data:
            return Response(
                json.dumps({"success": False, "message": "OTP expired or not found"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )
        hash_otp = sha256_hash(user_otp)
        if otp_data["otp"] == hash_otp:
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
                mimetype=APPLICATION_JSON,
            )
            frappe.cache().delete_value(f"otp_{user}")
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
            return Response(
                json.dumps({"message": "Invalid OTP"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )
    except Exception as e:
        frappe.log_error(message=str(e), title="OTP Validation Error")
        return Response(
            json.dumps({"message": "Error during OTP validation"}),
            status=401,
            mimetype=APPLICATION_JSON,
        )


# login api
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
                mimetype=APPLICATION_JSON,
            )
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception:
            return Response(
                json.dumps({"message": INVALID_SECURITY_PARAMETERS}),
                status=401,
                mimetype=APPLICATION_JSON,
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
                CUSTOMER_NAME_AS_EMAIL,
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

        # existing_otp = frappe.cache().get_value(f"otp_{api_key}")
        # if existing_otp and frappe.utils.now_datetime() < existing_otp["expires_at"]:
        #     return {
        #         "success": False,
        #         "message": "An OTP already exists. Please validate the current OTP.",
        #     }

        # Generate OTP without leading zeros
        otp = authenticate_for_2factor(api_key)
        hash_otp = sha256_hash(otp)
        frappe.cache().set_value(
            f"otp_{api_key}",
            {
                "otp": hash_otp,
                "token": result_data,
                "user": qid[0] if qid else {}
            },
        )

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
            mimetype=APPLICATION_JSON,
        )

    except Exception as e:
        frappe.log_error(message=str(e), title="2FA Token Generation Error")


@frappe.whitelist(allow_guest=True)
def resend_otp(user):
    
    """
    Resend the OTP to the user's email and replace only the OTP in the cache.
    """
    try:
        # Check if the user exists
        user = frappe.get_value("User", {"name": user}, "name")
        if not user:
            return Response(
                json.dumps({"success": False, "message": "User not found"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )

        # Fetch existing cache data
        existing_cache = frappe.cache().get_value(f"otp_{user}")
        if not existing_cache:
            return Response(
                json.dumps({"success": False, "message": "Resend OTP session has expired.Please login again"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )

        # Generate a new OTP
        otp_secret = get_otpsecret_for_(user)
        totp = TOTP(otp_secret, digits=6)
        otp = generate_totp_without_leading_zero(totp)
        hash_otp = sha256_hash(otp)  # Hash the new OTP

        # Update the existing cache data with the new OTP
        existing_cache["otp"] = hash_otp  # Replace the OTP
        # existing_cache["expires_at"] = frappe.utils.now_datetime() + timedelta(seconds=600)
        frappe.cache().set_value(f"otp_{user}", existing_cache)
        # Get user email
        customer_data = frappe.get_all(
            "Customer",
            fields=[CUSTOMER_NAME_AS_EMAIL],
            filters={"customer_name": ["like", user]},
        )
        if not customer_data or "email" not in customer_data[0]:
            return Response(
                json.dumps({"success": False, "message": "User email not found"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )
        user_email = customer_data[0]["email"]
        # Resend the OTP via email
        try:
            email_template = frappe.get_doc("Email Template", "gauth erpgulf")
            message = email_template.response_html
            message = message.format(otp=otp)  # Include the plaintext OTP in the email
            updated_html_content = message.replace("John Deo", user)
            subject = "Your OTP Code (Resent)"
            send_email_oci(user_email, subject, updated_html_content)
        except Exception as e:
            frappe.log_error(str(e), "Email Template or Sending Error")
            return Response(
                json.dumps({"message": "Email template not found or sending failed"}),
                status=500,
                mimetype=APPLICATION_JSON,
            )

        return Response(
            json.dumps({"success": True, "message": "OTP resent successfully"}),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    except Exception as e:
        frappe.log_error(message=str(e), title="Resend OTP Error")
        return Response(
            json.dumps({"message": "Failed to resend OTP", "error": str(e)}),
            status=500,
            mimetype=APPLICATION_JSON,
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
def generate_encrypted_token(text_for_encryption):
    """To generate test encrypted key from a text"""
    try:
        # Attempt to split the input into api_key, api_secret, and app_key
        api_key, api_secret, app_key = text_for_encryption.split("::")

        # Validate the user credentials
        try:
            validate_user = _check_password(
                api_key, api_secret
            )  # This will raise AuthenticationError on invalid credentials
        except frappe.AuthenticationError as e:
            # Handle invalid username or password error separately
            return Response(
                json.dumps({"message": str(e)}),
                status=401,
                mimetype=APPLICATION_JSON,
            )

        # Validate the application key using generate_token_secure
        try:
            # response = generate_token_secure(api_key, api_secret, app_key)
            app_key = base64.b64decode(app_key).decode("utf-8")
            validate_app_key = get_oauth_client(app_key)
            if not validate_app_key:
                return Response(
                    json.dumps({"message": "Invalid app key provided."}),
                    status=403,
                    mimetype=APPLICATION_JSON,
                )
            # if response.status_code != 200:
            #     return Response(
            #         json.dumps({"message": "Invalid app key provided."}),
            #         status=403,
            #         mimetype=APPLICATION_JSON,
            #     )
        except Exception as e:
            return Response(
                json.dumps({"message": f"Error validating app key: {str(e)}"}),
                status=500,
                mimetype=APPLICATION_JSON,
            )

        # If both user and app_key validation are successful, proceed to encrypt
        if validate_user and validate_app_key:
            current_totp = generate_totp()
            result = xor_encrypt_decrypt(text_for_encryption, current_totp)
            return base64.b64encode(result.encode()).decode()

    except ValueError:
        frappe.throw(
            "Invalid input structure. Please ensure the input contains app_key, api_key, and api_secret separated by '::'.",
            frappe.ValidationError,
        )
    except Exception as e:
        # Catch any other unexpected errors
        frappe.throw(f"An unexpected error occurred: {e}", frappe.ValidationError)


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


@frappe.whitelist(allow_guest=True)
def generate_token_encrypt_for_user_2fa_test(encrypted_key):
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
                mimetype=APPLICATION_JSON,
            )
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception:
            return Response(
                json.dumps({"message": INVALID_SECURITY_PARAMETERS}),
                status=401,
                mimetype=APPLICATION_JSON,
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
                CUSTOMER_NAME_AS_EMAIL,
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

        # existing_otp = frappe.cache().get_value(f"otp_{api_key}")
        # if existing_otp and frappe.utils.now_datetime() < existing_otp["expires_at"]:
        #     return {
        #         "success": False,
        #         "message": "An OTP already exists. Please validate the current OTP.",
        #     }

        # Generate OTP without leading zeros
        otp = authenticate_for_2factor(api_key)
        hash_otp = sha256_hash(otp)
        expiry_time = frappe.utils.now_datetime() + timedelta(minutes=10)
        frappe.cache().set_value(
            f"otp_{api_key}",
            {
                "otp": hash_otp,
                "token": result_data,
                "user": qid[0] if qid else {},
                "expires_at": expiry_time,
            },
        )
        # frappe.enqueue('gauth_erpgulf.gauth_erpgulf.2fa.cleanup_expired_otp', cache_key=f"otp_{api_key}", enqueue_after=10 * 60)
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
            mimetype=APPLICATION_JSON,
        )

    except Exception as e:
        frappe.log_error(message=str(e), title="2FA Token Generation Error")


def cleanup_expired_otp(cache_key):
    otp_data=frappe.cache().get_value(cache_key)
    if not otp_data:
        return
    expires_at=otp_data["expires_at"]
    if expires_at and frappe.utils.now_datetime()>expires_at:
        frappe.cache().delete_value(cache_key)
        frappe.log_error(message=f"Deleted Expired OTP Cache for {cache_key}",title="Cleaned Expired OTP")

