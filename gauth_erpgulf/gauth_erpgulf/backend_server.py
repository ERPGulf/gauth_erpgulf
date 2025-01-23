"""
This module contains backend server logic for gauth_erpgulf.
"""

import base64
import json
import os
import secrets
from email.utils import formataddr
from email.message import EmailMessage
import smtplib
import ipaddress
import ssl
import string
import re
from datetime import timedelta
import geoip2.database
import frappe
from frappe.core.doctype.user.user import update_password
from frappe.utils.data import sha256_hash
from frappe.utils.password import update_password as _update_password
import pyotp
import requests
from werkzeug.wrappers import Response
from frappe.utils import (
    cint,
    now,
    now_datetime,
    add_days,
    flt,
    get_url,
    time_diff_in_seconds,
)
# Constants
OAUTH_CLIENT = "OAuth Client"
OAUTH_TOKEN_URL = "/api/method/frappe.integrations.oauth2.get_token"
FIELD_NAME_AS_ID = "name as id"
FULL_NAME_ALIAS = "full_name as full_name"
BACKEND_SERVER_SETTINGS = "Backend Server Settings"
USER_NOT_FOUND_MESSAGE = "User not found"
NAME_AS_EMAIL = "name as email"
INVALID_SECURITY_PARAMETERS = "Security Parameters are not valid"
INVALID_OR_EXPIRED_KEYS="Invalid or expired key"
APPLICATION_JSON = "application/json"
MOBILE_NO_ALIAS = "mobile_no as mobile_no"
TWO_FA_TOKEN_EXPIRED = "2FA token expired"
GEO_IP_DATABASE = "geo-ip.mmdb"
COUNTRIES_AND_IP_ADDRESS = "Countries and IP address"
APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded"
FIELD_FOR_IP_AND_COUNTRY = [
    "countries",
    "api_allow",
    "desk_web_user_allow",
    "desk_user_allow",
]
COMPANY = "Company"
STATUS = 404
STATUS_200 = 200
STATUS_500 = 500
STATUS_400 = 500
ERROR = "An unexpected error occured"


@frappe.whitelist(allow_guest=True)
def get_backend_server_settings(*keys):
    """
    Fetch multiple settings from the BACKEND_SERVER_SETTINGS.
    """
    return {
        key: frappe.db.get_single_value(
            BACKEND_SERVER_SETTINGS,
            key) for key in keys
    }


@frappe.whitelist(allow_guest=False)
def is_api_request():
    """Check if the incoming request is an API request"""
    path = frappe.request.path
    headers = frappe.request.headers
    if path.startswith("/api"):
        return True
    is_authorized = "Authorization" in headers
    is_json = headers.get("Content-Type") == APPLICATION_JSON
    if is_authorized or is_json:
        return False


@frappe.whitelist(allow_guest=False)
def api_only():
    """Restrict access to API endpoints"""
    frappe.throw(
        frappe.request.path,
        frappe.PermissionError
        )


@frappe.whitelist(allow_guest=False)
def test_api():
    """Test endpoint for API-only access"""
    return "test api success"


@frappe.whitelist(allow_guest=False)
def xor_encrypt_decrypt(text, key):

    """Encrypt or decrypt text using XOR operation."""
    repeated_key = key * ((len(text) // len(key)) + 1)

    return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(text, repeated_key))


@frappe.whitelist(allow_guest=False)
def json_response(data, status=STATUS_200):
    """Return a standardized JSON response."""
    return Response(
        json.dumps(data),
        status=status,
        mimetype=APPLICATION_JSON)


@frappe.whitelist(allow_guest=False)
def generate_totp():
    """Generate TOTP token using 2FA secret."""
    settings = get_backend_server_settings("2fa_secret_key")
    secret = settings["2fa_secret_key"]
    totp = pyotp.TOTP(secret, interval=60)
    return totp.now()


@frappe.whitelist(allow_guest=False)
def get_oauth_client(app_key):
    """Fetch client_id and client_secret for an OAuth client."""
    client_id, client_secret, _ = frappe.db.get_value(
        OAUTH_CLIENT,
        {"app_name": app_key},
        ["client_id", "client_secret", "user"],
    )
    if not client_id:
        raise frappe.ValidationError(
            _(INVALID_SECURITY_PARAMETERS)
            )
    return client_id, client_secret


# api for master token
@frappe.whitelist(allow_guest=True)
def generate_token_secure(api_key, api_secret, app_key):
    """
    Generates a secure token using the provided API credentials.
    """
    try:
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except (ValueError, base64.binascii.Error) as decode_error:
            return Response(
                json.dumps(
                    {
                        "message": INVALID_SECURITY_PARAMETERS,
                        "error": str(decode_error),
                        "user_count": 0,
                    }
                ),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        try:
            client_id_value, client_secret_value = get_oauth_client(app_key)

        except ValueError as ve:
            return generate_error_response(
                ERROR,
                error=str(ve),
                status=STATUS_500
                )

        if client_id_value is None:
            return Response(
                json.dumps(
                    {
                        "message": INVALID_SECURITY_PARAMETERS,
                        "user_count": 0
                    }
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
        try:
            response = requests.request(
                "POST",
                url,
                data=payload,
                files=files,
                timeout=10
            )
        except requests.RequestException as request_error:
            return generate_error_response(
                "Error connecting to the authentication server",
                str(request_error),
                status=STATUS_500,
            )

        if response.status_code == STATUS_200:
            try:
                result_data = response.json()
                result_data["refresh_token"] = "XXXXXXX"
            except json.JSONDecodeError as json_error:
                return generate_error_response(
                    "Invalid JSON response",
                    error=str(json_error),
                    status=STATUS_500
                )

            return generate_success_response(result_data, status=STATUS_200)

        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)

    except ValueError as ve:
        return generate_error_response(
            ERROR,
            error=str(ve),
            status=STATUS_500
            )


# Api for user token
@frappe.whitelist(allow_guest=False)
def generate_token_secure_for_users(username, password, app_key):
    """
    Generate a secure token for user authentication.
    """
    frappe.log_error(
        title="Login attempt",
        message=str(username) + "    " + str(password) + "    " + str(app_key + "  "),
    )
    try:
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except ValueError as ve:
            return Response(
                json.dumps(
                    {
                        "message": INVALID_SECURITY_PARAMETERS,
                        "error": str(ve),
                        "user_count": 0,
                    }
                ),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if client_id_value is None:
            return Response(
                json.dumps(
                        {
                            "message": INVALID_SECURITY_PARAMETERS,
                            "user_count": 0
                        }
                    ),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        client_id = client_id_value  # Replace with your OAuth client ID
        client_secret = client_secret_value  # Replace with your OAuth client secret
        url = frappe.local.conf.host_name + OAUTH_TOKEN_URL
        payload = {
            "username": username,
            "password": password,
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        files = []
        response = requests.request(
            "POST",
            url,
            data=payload,
            files=files,
            timeout=10
            )
        qid = frappe.get_all(
            "User",
            fields=[
                FIELD_NAME_AS_ID,
                FULL_NAME_ALIAS,
                MOBILE_NO_ALIAS,
            ],
            filters={
                "email": ["like", username]
            },
        )
        if response.status_code == STATUS_200:
            result_data = response.json()
            result_data["refresh_token"] = "XXXXXXX"
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return generate_success_response(
                result,
                status=STATUS_200
            )
        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)
    except ValueError as ve:
        return generate_error_response(
            ERROR,
            error=str(ve),
            status=STATUS_500
        )

# Api for  checking user name  using token
@frappe.whitelist(allow_guest=False)
def whoami():
    """This function returns the current session user"""
    try:
        response_content = {
            "data":
                {
                    "user": frappe.session.user,
                }
        }
        return json_response(
            response_content,
            status=STATUS_200
        )
    except ValueError as ve:
        frappe.throw(ve)


# api for decrypting encrypt key
@frappe.whitelist(allow_guest=False)
def decrypt_2fa_key(encrypted_key):
    """This function used for decrypting the 2FA encrypted Key"""
    current_totp = generate_totp()
    encrypted = base64.b64decode(encrypted_key).decode()
    return current_totp, xor_encrypt_decrypt(encrypted, current_totp)


@frappe.whitelist(allow_guest=False)
def generate_token_encrypt(encrypted_key):
    """This function creates the master token using the encrypted key"""
    try:
        try:
            _, decrypted_key = decrypt_2fa_key(encrypted_key)
            api_key, api_secret, app_key = decrypted_key.split("::")
        except ValueError:
            return Response(
                json.dumps({"message": TWO_FA_TOKEN_EXPIRED, "user_count": 0}),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except ValueError as ve:
            return Response(
                json.dumps(
                        {
                            "message": str(ve),
                            "user_count": 0
                        }
                ),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        client_id, client_secret = get_oauth_client(app_key)
        client_id_value = client_id
        client_secret_value = client_secret
        if client_id_value is None:
            return Response(
                json.dumps(
                    {
                        "message": INVALID_SECURITY_PARAMETERS,
                        "user_count": 0
                    }
                ),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        url = frappe.local.conf.host_name + OAUTH_TOKEN_URL
        payload = {
            "username": api_key,
            "password": api_secret,
            "grant_type": "password",
            "client_id": client_id_value,
            "client_secret": client_secret_value,
        }
        files = []
        response = requests.request(
            "POST",
            url, data=payload, files=files, timeout=10)
        if response.status_code == STATUS_200:
            result_data = json.loads(response.text)
            return generate_success_response(result_data, status=STATUS_200)
        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)
    except ValueError as ve:
        return generate_error_response(
            ERROR,
            error=str(ve),
            status=STATUS_500
            )


@frappe.whitelist(allow_guest=False)
def test_encryption_xor(text_for_encryption, key):
    """
    Encrypt a text using XOR encryption.
    """
    repeated_key = key * ((len(text_for_encryption) // len(key)) + 1)

    result = "".join(
        chr(ord(c) ^ ord(k)) for c, k in zip(text_for_encryption, repeated_key)
    )

    return base64.b64encode(result.encode()).decode()


@frappe.whitelist(allow_guest=False)
def test_decryption_xor(text_for_decryption, key):
    """to decrypt a text using xor"""
    encrypted = base64.b64decode(text_for_decryption).decode()  # Decode Base64
    return "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(encrypted, key * (len(encrypted) // len(key) + 1))
    )


@frappe.whitelist(allow_guest=False)
def test_generate_2fa():
    """to generate a 2fa otp"""
    with open("io.claudion.com/api_encr.en", "r", encoding="utf-8") as file:
        secret = file.read().strip()
    totp = pyotp.TOTP(secret, interval=60)
    current_totp = totp.now()
    return current_totp


# Api for encrypt details used for token
@frappe.whitelist(allow_guest=False)
def test_generate_token_encrypt(text_for_encryption):
    """to generate a mastertoken using encrypted key"""
    current_totp = generate_totp()
    result = xor_encrypt_decrypt(text_for_encryption, current_totp)
    return base64.b64encode(result.encode()).decode()


# Api for encrypt user details
@frappe.whitelist(allow_guest=False)
def test_generate_token_encrypt_for_user(text_for_encryption):
    """to generate test encrypted key from a text"""
    current_totp = generate_totp()
    result = xor_encrypt_decrypt(text_for_encryption, current_totp)
    return base64.b64encode(result.encode()).decode()


@frappe.whitelist(allow_guest=False)
def generate_token_encrypt_for_user(encrypted_key):
    """to generate a usertoken using encrypted key"""
    try:
        # Decrypt the encrypted key
        _, decrypted_key = decrypt_2fa_key(encrypted_key)
        api_key, api_secret, app_key = decrypted_key.split("::")
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except (ValueError, base64.binascii.Error):
            return generate_error_response(
                INVALID_SECURITY_PARAMETERS,
                error="Invalid app_key format",
                status=401
            )
        # Retrieve OAuth client credentials
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if not client_id_value:
            return generate_error_response(
                INVALID_SECURITY_PARAMETERS,
                error="Invalid client ID or secret",
                status=401,
            )
        # Prepare payload for token request
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
        response = requests.post(url, data=payload, timeout=10)
        qid = frappe.get_all(
            "User",
            fields=[FIELD_NAME_AS_ID, FULL_NAME_ALIAS, MOBILE_NO_ALIAS],
            filters={"email": ["like", api_key]},
        )
        if response.status_code == STATUS_200:
            result_data = json.loads(response.text)
            result_data["refresh_token"] = "XXXXXXX"
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return generate_success_response(result, status=STATUS_200)
        else:
            return generate_error_response(
                "Token generation failed",
                error=response.text,
                status=response.status_code,
            )

    except ValueError as ve:
        return generate_error_response(
            "An unexpected error occurred",
            error=str(ve),
            status=STATUS_500
        )


@frappe.whitelist(allow_guest=False)
def get_user_name(user_email=None, mobile_phone=None):
    """to get username from useremail and mobile phone"""
    if mobile_phone is not None:
        user_details = frappe.get_all(
            "User",
            filters={"mobile_no": mobile_phone},
            fields=["name", "enabled"]
        )
    elif user_email is not None:
        user_details = frappe.get_all(
            "User", filters={"email": user_email}, fields=["name", "enabled"]
        )
    else:
        return Response(
            json.dumps({"data": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
            status=STATUS,
            mimetype=APPLICATION_JSON,
        )

    if len(user_details) >= 1:
        return generate_success_response(user_details[0], status=STATUS_200)

    else:
        return Response(
            json.dumps({"data": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
            status=STATUS,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def check_user_name(user_email=None, mobile_phone=None):
    """to check the username from useremail and mobile phone"""
    user_details_email = []
    user_details_mobile = []

    if user_email is not None:
        user_details_email = frappe.get_all(
            "User", filters={"email": user_email}, fields=["name", "enabled"]
        )
    if mobile_phone is not None:
        user_details_mobile = frappe.get_all(
            "User",
            filters={"mobile_no": mobile_phone},
            fields=["name", "enabled"]
        )

    if len(user_details_email) >= 1 or len(user_details_mobile) >= 1:
        return 1
    else:
        return 0

@frappe.whitelist(allow_guest=False)
def g_create_user(full_name, mobile_no, email, password=None, role="Customer"):
    """to create a user"""
    if not full_name or not mobile_no or not email:
        return Response(
            json.dumps({"message": "Missing required fields", "user_count": 0}),
            status=400,
            mimetype=APPLICATION_JSON,
        )
    if not password:
        password = generate_random_password(10)

    # Check if user already exists
    if check_user_name(user_email=email, mobile_phone=mobile_no) > 0:
        return Response(
            json.dumps({"message": "User already exists", "user_count": 1}),
            status=409,
            mimetype=APPLICATION_JSON,
        )

    try:
        frappe.get_doc(
            {
                "doctype": "User",
                "name": email,
                "first_name": full_name,
                "mobile_no": mobile_no,
                "new_password": password,
                "email": email,
                "username":email,
                "roles": [{"role": role}],
            }
        ).insert()

        frappe.get_doc(
            {
                "doctype": "Customer",
                "name": email,
                "customer_name": email,
                "custom_user": email,
                "full_name": full_name,
                "mobile_no": mobile_no,
                "email": email,
            }
        ).insert()

        g_generate_reset_password_key(
            email, send_email=True, password_expired=False, mobile=mobile_no, return_otp=True
        )
        # otp=sha256_hash(otp)
        # frappe.cache().set_value(
        #     f"otp_{email}",
        #     {
        #         "otp": otp,
        #         "expires_at": frappe.utils.now_datetime() + timedelta(seconds=60),
        #     },
        # )
        return Response(
            json.dumps({"data":"otp verification required"}),
            status=200,
            mimetype=APPLICATION_JSON
        )


    except ValueError as ve:
        return Response(
            json.dumps({"message": str(ve), "user_count": 0}),
            status=400,
            mimetype=APPLICATION_JSON,
        )

    except Exception as e:
        error_message = str(e)

        if "common password" in error_message:
            formatted_message = {"message": {"password": error_message}}
            return Response(
                json.dumps(formatted_message), status=400, mimetype=APPLICATION_JSON
            )

        return Response(
            json.dumps({"message": error_message, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def g_generate_reset_password_key(
    recipient,
    mobile="",
    send_email=True,
    password_expired=False,
    return_otp=False
):

    if mobile == "":
        return Response(
            json.dumps({"message": "Mobile or Email  not found", "user_count": 0}),
            status=404,
            mimetype=APPLICATION_JSON,
        )
    try:
        if (
            len(
                frappe.get_all("User", filters={"name": recipient, "mobile_no": mobile})
            )
            < 1
        ):
            return Response(
                json.dumps(
                    {"message": "Email or Mobile number not found", "user_count": 0}
                ),
                status=404,
                mimetype=APPLICATION_JSON,
            )

        
        key = "".join(secrets.choice(string.digits) for _ in range(6))
        doc2 = frappe.get_doc("User", recipient)
        doc2.reset_password_key = sha256_hash(key)
        doc2.last_reset_password_key_generated_on = now_datetime()
        doc2.save(ignore_permissions=True)
        url = "/update-password?key=" + key
        msg = frappe.get_doc("Email Template", "gauth erpgulf")
        message = msg.response_html.replace("{otp}", key)
        name = frappe.get_all(
            "User",
            fields=["full_name"],
            filters={"name": recipient, "mobile_no": mobile},
        )
        full_name = name[0].get("full_name")
        updated_html_content = message.replace("John Deo", full_name)
        subject = "OTP"

        if password_expired:
            url = "/update-password?key=" + key + "&password_expired=true"
        # send_sms_expertexting(mobile,key)  # stop this on testing cycle as it send SMSes
        # send_sms_vodafone(mobile, urllib.parse.quote(f"Your Validation code for DallahMzad is {key} Thank You.  \n \n  رمز التحقق الخاص بك لـ DallahMzad هو {key} شكرًا لك."))
        link = get_url(url)
        if send_email:
            send_email_oci(recipient, subject, updated_html_content)
            # send_email_oci(user,"Claudion Account Validation Key","Please use this key to activate or reset your  account password. This key valid only for 10 minutes and for one-time use only. Your key is " + key)

        if return_otp:
            return key

        return Response(
            json.dumps({
                "reset_key": "XXXXXX",
                "generated_time": str(now_datetime()),
                "URL": "XXXXXXXX",
            }),
            status=200,
            mimetype=APPLICATION_JSON,
        )
    except Exception as e:
        return Response(
            json.dumps({"message": str(e), "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )

@frappe.whitelist(allow_guest=False)
def send_email_oci(recipient, subject, body_html):
    """send an email to recipient with subject"""
    settings = get_backend_server_settings(
        "sender", "sender_name", "user_smtp", "password_smtp", "host", "port"
    )
    sender = settings["sender"]
    sender_name = settings["sender_name"]
    user_smtp = settings["user_smtp"]
    password_smtp = settings["password_smtp"]
    host = settings["host"]
    port = settings["port"]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, sender))
    msg["To"] = recipient
    msg.set_content(body_html, subtype="html")
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
    except ValueError as ve:
        return f"Error: {ve}"


@frappe.whitelist(allow_guest=False)
def is_user_available(user_email=None, mobile_phone=None):
    """to check if user is available or not"""
    response = ""
    status_code = 0
    try:

        if mobile_phone is not None:
            mobile_count = len(
                frappe.get_all(
                    "User",
                    filters={"mobile_no": mobile_phone}
                    )
            )
        else:
            mobile_count = 0
        if user_email is not None:
            email_count = len(frappe.get_all("User", {"email": user_email}))
        else:
            email_count = 0
        if mobile_count >= 1 and email_count < 1:
            response = {"message": "Mobile exists", "user_count": mobile_count}
            status_code = STATUS_200
        if email_count >= 1 and mobile_count < 1:
            response = {"message": "Email exists", "user_count": email_count}
            status_code = STATUS_200
        if mobile_count >= 1 and email_count >= 1:
            response = {
                "message": "Mobile and Email exists",
                "user_count": mobile_count,
            }
            status_code = STATUS_200
        if mobile_count < 1 and email_count < 1:
            response = {
                    "message": "Mobile and Email does not exist",
                    "user_count": 0
                }
            status_code = STATUS
        return Response(
            json.dumps(response), status=status_code, mimetype=APPLICATION_JSON
        )

    except ValueError as e:
        return generate_error_response(
            ERROR,
            error=str(e),
            status=STATUS_500
        )


@frappe.whitelist(allow_guest=False)
def g_update_password(username, password):
    """to update the user password"""
    try:
        if len(frappe.get_all("User", {"email": username})) < 1:
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE}),
                status=STATUS,
                mimetype=APPLICATION_JSON,
            )
        _update_password(username, password)
        qid = frappe.get_all(
            "User",
            fields=[
                FIELD_NAME_AS_ID,
                FULL_NAME_ALIAS,
                "mobile_no as phone",
                NAME_AS_EMAIL,
            ],
            filters={"email": ["like", username]},
        )
        result = {
            "message": "Password successfully updated",
            "user_details": qid[0] if qid else {},
        }
        # frappe.db.commit()
        return json_response(result)
    except ValueError as ve:
        return generate_error_response(
            ERROR,
            error=str(ve),
            status=STATUS_500)


@frappe.whitelist(allow_guest=False)
def g_delete_user(email, mobile_no):
    """to delete the user"""
    try:
        if (
            len(
                frappe.get_all(
                    "User",
                    {
                        "name": email,
                        "email": email,
                        "mobile_no": mobile_no
                    }
                )
            )
            < 1
        ):
            return Response(
                json.dumps(
                    {
                        "message": USER_NOT_FOUND_MESSAGE, "user_count": 0
                    }
                ),
                status=STATUS,
                mimetype=APPLICATION_JSON,
            )

        _ = (
            frappe.db.delete(
                "User",
                {
                    "name": email,
                    "email": email,
                    "mobile_no": mobile_no
                }
            ),
        )
        _ = frappe.db.delete(
            "Customer",
            {
                "name": email,
                "customer_name": email,
                "mobile_no": mobile_no,
            },
        )

        return json_response(
                {
                    "message": "User successfully deleted",
                    "user_count": 1
                }
            )
    except ValueError as ve:
        return generate_error_response(
            ERROR,
            error=str(ve),
            status=STATUS_500)


@frappe.whitelist(allow_guest=False)
def validate_email(email_to_validate):
    """
    Validate the format of the email and check if it is blocked.
    """
    def is_valid_email(email):
        """
        Check if the email format is valid using regex.
        """
        return re.match(
                r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email
            ) is not None

    def get_domain_name(email):
        """
        Extract the domain name from the email address.
        """
        return email.split("@")[-1] if "@" in email else None

    if not is_valid_email(email_to_validate):
        return Response(
            json.dumps(
                {
                    "blocked": True, "reason": "Email format not correct"
                }
            ),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    domain_name = get_domain_name(email_to_validate)

    url = (
            f"https://www2.istempmail.com/api/check/"
            f"CirMirL3dAHELe8pKdUeG55KV3qy6weU/{domain_name}"
    )

    payload = {}
    headers = {}

    try:
        response = requests.get(url, headers=headers, data=payload, timeout=10)
        api_response = response.json()
        blocked = api_response.get("blocked", False)
    except requests.exceptions.RequestException:
        blocked = False
    if blocked:
        return Response(
            json.dumps({
                "blocked": True,
                "reason": "Temporary email not accepted."
                "Please provide your company email",
            }),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    domain_js_path = os.path.join(
        os.path.dirname(__file__), "..", "public", "domain.js"
    )

    try:
        with open(domain_js_path, "r") as file:
            domain_js_content = file.read()

        domains_list = json.loads(domain_js_content)

        if domain_name in domains_list:
            return Response(
                json.dumps(
                    {
                        "blocked": True,
                        "reason": "Public email not accepted."
                        "Please provide your company email",
                    }
                ),
                status=200,
                mimetype=APPLICATION_JSON,
            )
        else:
            return Response(
                json.dumps({"blocked": False}),
                status=200,
                mimetype=APPLICATION_JSON,
            )

    except Exception:
        return Response(
            json.dumps({"blocked": False}),
            status=400,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def g_user_enable(username, email, mobile_no, enable_user: bool = True):
    """to Enable the  User"""
    try:
        if (
            len(
                frappe.get_all(
                    "User",
                    {
                        "name": username,
                        "email": email,
                        "mobile_no": mobile_no
                    }
                )
            )
            < 1
        ):
            return Response(
                json.dumps(
                    {
                        "message": USER_NOT_FOUND_MESSAGE,
                        "user_count": 0
                    }
                ),
                status=STATUS,
                mimetype=APPLICATION_JSON,
            )

        frappe.db.set_value(
                "User", username,
                "enabled", enable_user
            )
        status_message = (
            f"User successfully {'enabled' if enable_user else 'disabled'}"
        )
        return json_response(
            {
                "message": status_message,
                "user_count": 1,
            }
        )
    except ValueError as ve:
        return generate_error_response(
                ERROR,
                error=str(ve),
                status=STATUS_500
            )


@frappe.whitelist(allow_guest=False)
def g_update_password_using_usertoken(password):
    """to update user password using user token"""
    try:
        username = frappe.session.user
        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps(
                    {
                        "message": USER_NOT_FOUND_MESSAGE,
                        "user_count": 0
                    }
                ),
                status=STATUS,
                mimetype=APPLICATION_JSON,
            )
        _update_password(username, password, logout_all_sessions=True)
        qid = frappe.get_all(
            "Customer",
            fields=[
                # "name as id",
                "customer_name as  full_name",
                "mobile_no as phone",
                # NAME_AS_EMAIL,
            ],
            filters={
                    "customer_name": ["like", username]
                },
        )
        result = {
            "message": "Password successfully updated",
            "user_details": qid[0] if qid else {},
        }
        return generate_success_response(result, status=STATUS_200)

    except ValueError as ve:
        return generate_error_response(
            ERROR,
            error=str(ve),
            status=STATUS_500)


@frappe.whitelist(allow_guest=False)
def g_update_password_using_reset_key(new_password, reset_key, username):
    """to update user password using reset key"""
    try:

        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps(
                    {
                        "message": USER_NOT_FOUND_MESSAGE,
                        "user_count": 0
                    }
                ),
                status=STATUS,
                mimetype=APPLICATION_JSON,
            )
        if not new_password:
            return Response(
                json.dumps({"message": "Missing New Password Credential"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )
        update_password(new_password=new_password, key=reset_key)

        if frappe.local.response.http_status_code == 410:
            return Response(
                json.dumps({"message": INVALID_OR_EXPIRED_KEYS}),
                status=frappe.local.response.http_status_code,
                mimetype=APPLICATION_JSON,
            )
        if frappe.local.response.http_status_code == 400:
            return Response(
                json.dumps({"message": INVALID_OR_EXPIRED_KEYS}),
                status=frappe.local.response.http_status_code,
                mimetype=APPLICATION_JSON,
            )
        frappe.local.response.http_status_code = STATUS_200
        if frappe.local.response.http_status_code == STATUS_200:
            return Response(
                json.dumps({"message": "Password Successfully updated"}),
                status=frappe.local.response.http_status_code,
                mimetype=APPLICATION_JSON,
            )

    except ValueError as ve:
        return Response(
            json.dumps({"message": str(ve), "user_count": 0}),
            status=400,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def login_time():
    """To get the Login Details of user"""

    username = frappe.session.user
    doc = frappe.get_all(
        "User Log Details",
        fields=["time"],
        filters={"username": ["like", username]}
    )
    return doc


# to validate ip
@frappe.whitelist(allow_guest=False)
def validate_country(ip_address):
    """To validate IP address Country"""

    reader = geoip2.database.Reader(GEO_IP_DATABASE)
    response = reader.country(ip_address)

    return response.country.name


@frappe.whitelist(allow_guest=False)
def get_restriction_by_ip(source_ip_address):
    """Fetch restrictions by IP address."""
    return frappe.get_all(
        COUNTRIES_AND_IP_ADDRESS,
        filters={
                "parent": BACKEND_SERVER_SETTINGS,
                "countries": source_ip_address
            },
        fields=FIELD_FOR_IP_AND_COUNTRY,
    )


@frappe.whitelist(allow_guest=False)
def get_country_from_ip(ip_address):
    """Retrieve the country name from an IP address."""
    reader = geoip2.database.Reader(GEO_IP_DATABASE)
    response = reader.country(ip_address)
    return response.country.name


@frappe.whitelist(allow_guest=False)
def get_restriction_by_country(country):
    """Fetch restrictions by country."""
    return frappe.get_all(
        COUNTRIES_AND_IP_ADDRESS,
        filters={
            "parent": BACKEND_SERVER_SETTINGS,
            "countries": country,
        },
        fields=FIELD_FOR_IP_AND_COUNTRY,
    )


@frappe.whitelist(allow_guest=False)
def handle_api_restrictions(restriction, ip_address):
    """Handle API access restrictions."""
    if restriction and restriction[0].get("api_allow") == 0:
        frappe.throw(
            msg=f"Access to this API is not allowed. IP: {ip_address}",
            exc=frappe.PermissionError,
        )


@frappe.whitelist(allow_guest=False)
def deny_access(user_type):
    """Deny access and send an appropriate response."""
    frappe.throw(
        f"Access to this {user_type} from your location is not allowed "
        + frappe.local.request.headers.get("X-Forwarded-For")
    )
    frappe.local.response["http_status_code"] = 403


@frappe.whitelist(allow_guest=False)
def handle_non_api_restrictions(restriction):
    """Handle restrictions for non-API access."""
    user_type = frappe.get_all(
        "User", fields=["user_type"], filters={"name": frappe.session.user}
    )

    if (
        user_type[0].get("user_type") == "System User"
        and restriction[0].get("desk_user_allow") == 0
    ):
        deny_access("system user")
        return "system user"

    if (
        user_type[0].get("user_type") == "Website User"
        and restriction[0].get("desk_web_user_allow") == 0
    ):
        deny_access("web user")
        return "web user"


@frappe.whitelist(allow_guest=True)
def check_country_restriction(*args, **kwargs):
    """to check the restriction based on country"""
    _ = args  # Explicitly ignore args
    _ = kwargs  # Explicitly ignore args
    try:
        source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")
        restriction = get_restriction_by_ip(source_ip_address)
        if not restriction:
            user_country = get_country_from_ip(source_ip_address)
            restriction = get_restriction_by_country(user_country)
        if restriction:
            if frappe.local.request.path.startswith("/api/method"):
                handle_api_restrictions(restriction, source_ip_address)
                return
            else:
                handle_non_api_restrictions(restriction)
                return
    except ValueError:
        pass


@frappe.whitelist(allow_guest=False)
def generate_random_password(length=10):
    """To generate a Random Password"""

    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(characters) for _ in range(length))


@frappe.whitelist(allow_guest=False)
def get_restriction_by_ip_1(source_ip_address):
    """Fetch restrictions by IP address or CIDR block."""
    restrictions = frappe.get_all(
        COUNTRIES_AND_IP_ADDRESS,
        filters={"parent": BACKEND_SERVER_SETTINGS},
        fields=[
            "countries",  # This field now contains both IPs and CIDR blocks
            "api_allow",
            "desk_web_user_allow",
            "desk_user_allow",
        ],
    )
    for restriction in restrictions:
        country_entry = restriction.get("countries")
        try:
            if "/" in country_entry:
                ip_addr = ipaddress.ip_address(source_ip_address)
                ip_network = ipaddress.ip_network(country_entry)

                if ip_addr in ip_network:
                    return [restriction]

            else:
                # Treat it as a single IP address
                if source_ip_address == country_entry:
                    return [restriction]
        except ValueError:
            # Ignore invalid IP or CIDR formats in the database
            frappe.log_error(
                f"Invalid IP or CIDR format:{country_entry}",
                "IP Restriction Error"
            )
    return []


def generate_error_response(message, error, status=STATUS_500):
    """Generate a standardized error response in JSON format."""
    return Response(
        json.dumps(
            {
                "message": message,
                "error": error,
                "user_count": 0
            }
        ),
        status=status,
        mimetype=APPLICATION_JSON,
    )


def generate_success_response(data, status=STATUS_200):
    """Generate a standardized success response in JSON format."""
    return Response(
        json.dumps({"data": data}),
        status=status,
        mimetype=APPLICATION_JSON,
    )


@frappe.whitelist(allow_guest=False)
def resend_otp_for_reset_key(user):
    """
    Resend the OTP for resetting the password.
    """
    try:
        if not user:
            return Response(
                json.dumps(
                    {
                        "success": False,
                        "message": "User Field cannot be empty."
                    }
                ),
                status=400,
                mimetype=APPLICATION_JSON,
            )

        user_data=frappe.db.get_value("User",{"name":user},["name"])
        if not user_data:
            return Response(
                json.dumps(
                    {
                        "success": False,
                        "message": f"No user found: {user}"
                    }
                ),
                status=400,
                mimetype=APPLICATION_JSON,
            )

        user_mobile = frappe.get_all(
            "User",
            fields=["mobile_no"],
            filters={"name": user},
        )

        if not user_mobile:
            return Response(
                json.dumps(
                    {
                        "success": False,
                        "message": f"No mobile number found for user: {user}"
                    }
                ),
                status=400,
                mimetype=APPLICATION_JSON,
            )

        mobile = user_mobile[0]["mobile_no"]
        if not mobile:
            return Response(
                json.dumps(
                    {
                        "success": False,
                        "message": f"No mobile number associated with user: {user}"
                    }
                ),
                status=400,
                mimetype=APPLICATION_JSON,
            )

        # Generate OTP and send it
        g_generate_reset_password_key(
            user, send_email=True, password_expired=False, mobile=mobile, return_otp=False
        )

        return Response(
            json.dumps(
                {
                    "success": True,
                    "message": "OTP resent successfully"
                }
            ),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    except Exception as e:
        return Response(
            json.dumps(
                {
                    "success": False,
                    "message": "Failed to resend OTP",
                    "error": str(e)
                }
            ),
            status=500,
            mimetype=APPLICATION_JSON,
        )
