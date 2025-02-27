"""This module contains the functions for two-factor authentication."""
import os
import json
import base64
from datetime import datetime
from base64 import b32encode
import frappe.utils
import requests
from werkzeug.wrappers import Response
from pyotp import TOTP
import frappe
import frappe.defaults
from frappe.utils.password import encrypt, decrypt
from frappe.utils import (
    sha256_hash,
)
from frappe.utils.password import check_password as _check_password
from gauth_erpgulf.gauth_erpgulf.backend_server import (
    xor_encrypt_decrypt,
    send_email_oci,
    decrypt_2fa_key,
    generate_totp,
    get_oauth_client,
    generate_error_response,
    generate_success_response
)
from frappe.utils.response import Response


PARENT_FOR_DEFAULTS = "__2fa"
OAUTH_TOKEN_URL = "/api/method/frappe.integrations.oauth2.get_token"
FIELD_NAME_AS_ID = "name as id"
FULL_NAME_ALIAS = "full_name as full_name"
USER_NOT_FOUND_MESSAGE = "User not found"
INVALID_SECURITY_PARAMETERS = "Security Parameters are not valid"
APPLICATION_JSON = "application/json"
TWO_FA_TOKEN_EXPIRED = "2FA token expired"
STATUS_401 = 401
STATUS_500 = 500
STATUS_200 = 200
STATUS_400 = 400
MOBILE_NO_ALIAS = "mobile_no as mobile_no"
CUSTOMER_NAME_AS_EMAIL = "customer_name as email"


# API for encrypted user token
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
            frappe.local.response = {
                "message": USER_NOT_FOUND_MESSAGE,
                "http_status_code": STATUS_400
            }
            return generate_error_response(USER_NOT_FOUND_MESSAGE,None,STATUS_400)
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
            frappe.local.response = {
                "success": False,
                "message": "OTP expired or not found",
                "http_status_code": STATUS_400
            }
            return generate_error_response("OTP expired or not found",None,STATUS_400)
        hash_otp = sha256_hash(user_otp)
        if otp_data["otp"] == hash_otp:
            refresh_token = otp_data["token"].get("refresh_token", None)
            result_data = {
                        "success": True,
                        "message": "OTP validated successfully",
                        "token": otp_data["token"],
                        "user": customer_data,
                    }
            response = Response(
                json.dumps(
                    result_data
                ),
                status = STATUS_200,
                mimetype = APPLICATION_JSON,
            )

            frappe.local.response = {
                "data": result_data,
                "http_status_code": STATUS_200
            }
            if refresh_token:
                response.set_cookie(
                    "refresh_token",
                    refresh_token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    max_age=30 * 24 * 60 * 60,  # Expiry in 30 days
                )
            user_log = frappe.get_doc(
            {
                "doctype" : "User Log Details",
                "username" : user,
                "time" : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        )
            user_log.insert(ignore_permissions = True)
            frappe.db.commit()
            frappe.cache().delete_value(f"otp_{user}")
            return generate_success_response(result_data,STATUS_200)

        else:
            frappe.local.response = {
                "message": "Invalid OTP",
                "http_status_code": STATUS_400
            }
            return generate_error_response("Invalid OTP",None,STATUS_400)

    except Exception as e:
        frappe.local.response = {
                "message": "Error during OTP validation",
                "http_status_code": STATUS_401
            }
        return generate_error_response("Error during OTP validation", None, STATUS_401)



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
            frappe.local.response = {
                "message": INVALID_SECURITY_PARAMETERS,
                "http_status_code": STATUS_401,
            }
            return generate_error_response(
                TWO_FA_TOKEN_EXPIRED,
                None,
                STATUS_401,
            )
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception:
            frappe.local.response = {
                "message": INVALID_SECURITY_PARAMETERS,
                "http_status_code": STATUS_401,
            }
            return generate_error_response(
                message=INVALID_SECURITY_PARAMETERS,
                error="Invalid app_key format.",
                status = STATUS_401,
            )
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if client_id_value is None:
            frappe.local.response = {
                "message": INVALID_SECURITY_PARAMETERS,
                "http_status_code": STATUS_401,
            }
            return generate_error_response(
                message=INVALID_SECURITY_PARAMETERS,
                error="Invalid client ID or secret.",
                status = STATUS_401,
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
        if response.status_code == STATUS_200:
            try:
                result_data = response.json()
            except json.JSONDecodeError as json_error:
                frappe.local.response = {
                "data": json_error,
                "http_status_code": STATUS_500,
            }
                return generate_error_response("Invalid JSON response",str(json_error),STATUS_500)
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
            frappe.local.response = {
                "data": "Email Sending Error.",
                "http_status_code": STATUS_500,
            }
            return generate_error_response("Email template not found or sending failed",STATUS_500)
        frappe.local.response = {
                "message" : "OTP verification is required",
                "http_status_code" : STATUS_200,
            }
        # Return OTP required response
        return generate_success_response("OTP verification is required",STATUS_200)

    except Exception as e:
        frappe.log_error(message=str(e), title="2FA Token Generation Error")
        frappe.local.response = {
                "message" : "2FA Token Generation Error",
                "http_status_code" : STATUS_500,
            }
        return generate_error_response("2FA Token Generation Error",None,STATUS_500)


@frappe.whitelist(allow_guest=True)
def resend_otp(user):
    """
    Resend the OTP to the user's email and replace only the OTP in the cache.
    """
    try:
        # Check if the user exists
        user = frappe.get_value("User", {"name": user}, "name")
        if not user:
            frappe.local.response = {
                "success": False,
                "message": USER_NOT_FOUND_MESSAGE,
                "http_status_code": STATUS_400
            }
            return generate_error_response(USER_NOT_FOUND_MESSAGE,None,STATUS_400)

        # Fetch existing cache data
        existing_cache = frappe.cache().get_value(f"otp_{user}")
        if not existing_cache:
            frappe.local.response = {
                "success": False,
                "message": "Resend OTP session has expired.Please login again",
                "http_status_code": STATUS_400
            }
            return generate_error_response("Resend OTP session has expired.Please login again",None,STATUS_400)
        # Generate a new OTP
        otp_secret = get_otpsecret_for_(user)
        totp = TOTP(otp_secret, digits=6)
        otp = generate_totp_without_leading_zero(totp)
        hash_otp = sha256_hash(otp)  # Hash the new OTP
        existing_cache["otp"] = hash_otp  # Replace the OTP
        frappe.cache().set_value(f"otp_{user}", existing_cache)
        data=frappe.cache().get_value(f"otp_{user}")
        customer_data = frappe.get_all(
            "Customer",
            fields=[CUSTOMER_NAME_AS_EMAIL],
            filters={"customer_name": ["like", user]},
        )
        if not customer_data or "email" not in customer_data[0]:
            frappe.local.response = {
                "message": "User email not found",
                "http_status_code": STATUS_400
            }
            return generate_error_response("User email not found",None,STATUS_400)
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
            frappe.local.response = {
                "message": "Email template not found or sending failed",
                "http_status_code": STATUS_500
            }
            return generate_error_response("Email template not found or sending failed",None,STATUS_500)
        frappe.local.response = {
                "success": True,
                "message": "OTP resent successfully",
                "http_status_code": STATUS_200
            }
        return generate_success_response("OTP resent successfully",STATUS_200)
    except Exception as e:
        frappe.log_error(message=str(e), title="Resend OTP Error")
        return generate_error_response("Failed to resend OTP",str(e),STATUS_500)


@frappe.whitelist(allow_guest=True)
def generate_encrypted_token(text_for_encryption):
    """To generate test encrypted key from a text"""
    try:
        api_key, api_secret, app_key = text_for_encryption.split("::")
        try:
            validate_user = _check_password(
                api_key, api_secret
            )  # This will raise AuthenticationError on invalid credentials
        except frappe.AuthenticationError as e:
            # Handle invalid username or password error separately
            frappe.local.response = {
                "message": str(e),
                "http_status_code": STATUS_401
            }
            return generate_error_response(str(e), None, STATUS_401)
        try:
            # response = generate_token_secure(api_key, api_secret, app_key)
            app_key = base64.b64decode(app_key).decode("utf-8")
            validate_app_key = get_oauth_client(app_key)
            if not validate_app_key:
                frappe.local.response = {
                "message": str(e),
                "http_status_code": 403
            }
                return generate_error_response("Invalid app key provided.",None,403)

        except Exception as e:
            frappe.local.response = {
                "message": str(e),
                "http_status_code": STATUS_500
            }
            return generate_error_response(f"Error validating app key: {str(e)}",None,STATUS_500)

        # If both user and app_key validation are successful, proceed to encrypt
        if validate_user and validate_app_key:
            current_totp = generate_totp()
            result = xor_encrypt_decrypt(text_for_encryption, current_totp)
            encoded_result = base64.b64encode(result.encode()).decode()
            frappe.local.response = {
                "message": encoded_result,
                "http_status_code": STATUS_200  # Status code 200 for success
            }
            return generate_success_response(encoded_result,STATUS_200)

    except ValueError:
        frappe.throw(
            "Invalid input structure. Please ensure the input contains app_key, api_key, and api_secret separated by '::'.",
            frappe.ValidationError,
        )
    except Exception as e:
        # Catch any other unexpected errors
        frappe.throw(f"An unexpected error occurred: {e}", frappe.ValidationError)

