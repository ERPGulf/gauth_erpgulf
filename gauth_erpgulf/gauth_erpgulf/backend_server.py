import random
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
from frappe.utils.password import update_password as _update_password
from frappe.utils import get_url
import pyotp
import requests
import ipaddress
from werkzeug.wrappers import Response
import firebase_admin
from firebase_admin import credentials, exceptions, messaging

# Constants
OAUTH_CLIENT = "OAuth Client"
OAUTH_TOKEN_URL = "/api/method/frappe.integrations.oauth2.get_token"
FIELD_NAME_AS_ID = "name as id"
FULL_NAME_ALIAS = "full_name as full_name"
BACKEND_SERVER_SETTINGS = "Backend Server Settings"
USER_NOT_FOUND_MESSAGE = "User not found"
NAME_AS_EMAIL = "name as email"
INVALID_SECURITY_PARAMETERS = "Security Parameters are not valid"
APPLICATION_JSON = "application/json"


@frappe.whitelist(allow_guest=False)
def getToken2(self):
    pass


@frappe.whitelist(allow_guest=False)
def is_api_request():
    path = frappe.request.path
    headers = frappe.request.headers

    # Check if the path starts with /api
    if path.startswith("/api"):
        return True

    # Check if Authorization or JSON Content-Type headers are present
    is_authorized = "Authorization" in headers
    is_json = headers.get("Content-Type") == "application/json"
    if is_authorized or is_json:
        return False


@frappe.whitelist(allow_guest=False)
def api_only():
    frappe.throw(frappe.request.path, frappe.PermissionError)


@frappe.whitelist(allow_guest=False)
def test_api():
    return "test api success"


@frappe.whitelist(allow_guest=False)
def xor_encrypt_decrypt(text, key):
    """Encrypt or decrypt text using XOR operation."""
    return "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(
            text,
            key * ((len(text) // len(key)) + 1)
        )
    )


@frappe.whitelist(allow_guest=False)
def json_response(data, status=200):
    """Return a standardized JSON response."""
    return Response(json.dumps(data), status=status, mimetype=APPLICATION_JSON)


@frappe.whitelist(allow_guest=False)
def generate_totp():
    """Generate TOTP token using 2FA secret."""
    secret = frappe.db.get_single_value(
        BACKEND_SERVER_SETTINGS, "2fa_secret_key"
        )
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
        raise frappe.ValidationError(_(INVALID_SECURITY_PARAMETERS))
    return client_id, client_secret


# api for master token
@frappe.whitelist(allow_guest=True)
def generate_token_secure(api_key, api_secret, app_key):
    """
    Generates a secure token using the provided API credentials.
    Returns:
        Response: A JSON response containing the secure token or error message.
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
        except Exception as e:
            return Response(
                json.dumps(
                    {"message": "An unexpected error occured",
                     "error": str(e)}
                    ),
                status=500,
                mimetype=APPLICATION_JSON,
            )

        if client_id_value is None:
            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS,
                     "user_count": 0}
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
                "POST", url, data=payload, files=files, timeout=10
            )
        except requests.RequestException as request_error:
            return Response(
                json.dumps(
                    {
                        "message": "Error connecting to the authentication server",
                        "error": str(request_error),
                    }
                ),
                status=500,
                mimetype=APPLICATION_JSON,
            )

        if response.status_code == 200:
            try:
                result_data = response.json()
                result_data["refresh_token"] = "XXXXXXX"
            except json.JSONDecodeError as json_error:
                return Response(
                    json.dumps(
                        {"message": "Invalid JSON response",
                         "error": str(json_error)}
                    ),
                    status=500,
                    mimetype=APPLICATION_JSON,
                )

            return Response(
                json.dumps({"data": result_data}),
                status=200,
                mimetype=APPLICATION_JSON,
            )

        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


# Api for user token
@frappe.whitelist(allow_guest=False)
def generate_token_secure_for_users(username, password, app_key):
    """
    Generate a secure token for user authentication.
    Returns:
        str: A securely generated token for the user.
    """
    frappe.log_error(
        title="Login attempt",
        message=str(username) + "    " + str(password) + "    " + str(app_key + "  "),
    )
    try:
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception as e:
            return Response(
                json.dumps({"message": e, "user_count": 0}),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if client_id_value is None:
            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS,
                     "user_count": 0}
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
        response = requests.request("POST", url, data=payload, files=files, timeout=10)
        qid = frappe.get_list(
            "User",
            fields=[
                FIELD_NAME_AS_ID,
                FULL_NAME_ALIAS,
                "mobile_no as mobile_no",
            ],
            filters={"email": ["like", username]},
        )
        if response.status_code == 200:
            result_data = response.json()
            result_data["refresh_token"] = "XXXXXXX"
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return Response(
                json.dumps({"data": result}),
                status=200,
                mimetype=APPLICATION_JSON
            )
        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


# Api for  checking user name  using token
@frappe.whitelist(allow_guest=False)
def whoami():
    """This function returns the current session user"""
    try:
        response_content = {
            "data": {
                "user": frappe.session.user,
            }
        }
        return json_response(response_content, status=200)
    except Exception as e:
        frappe.throw(e)


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
                json.dumps({"message": "2FA token expired", "user_count": 0}),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception as e:
            return Response(
                json.dumps({"message": str(e), "user_count": 0}),
                status=401,
                mimetype=APPLICATION_JSON,
            )
        client_id, client_secret = get_oauth_client(app_key)
        client_id_value = client_id
        client_secret_value = client_secret
        if client_id_value is None:
            return Response(
                json.dumps({"message": INVALID_SECURITY_PARAMETERS,
                            "user_count": 0}),
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
        headers = {"Content-Type": APPLICATION_JSON}
        response = requests.request("POST", url, data=payload, files=files)
        if response.status_code == 200:
            result_data = json.loads(response.text)
            return Response(
                json.dumps({"data": result_data}),
                status=200,
                mimetype=APPLICATION_JSON,
            )
        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def test_encryption_xor(text_for_encryption, key):
    """
    Encrypt a text using XOR encryption.
    """
    repeated_key = key * ((len(text_for_encryption) // len(key)) + 1)

    result = "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(text_for_encryption, repeated_key)
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


# API for encrypted user token
@frappe.whitelist(allow_guest=False)
def generate_token_encrypt_for_user(encrypted_key):
    """to generate a usertoken using encrypted key"""
    try:
        try:

            _, decrypted_key = decrypt_2fa_key(encrypted_key)

            api_key, api_secret, app_key = decrypted_key.split("::")

        except ValueError:
            return Response(
                json.dumps(
                    {"message": "2FA token expired", "user_count": 0}
                    ),
                status=401,
                mimetype=APPLICATION_JSON,
            )

        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception as e:
            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS,
                     "user_count": 0}
                    ),
                status=401,
                mimetype=APPLICATION_JSON,
            )

        client_id_value, client_secret_value = get_oauth_client(app_key)

        if client_id_value is None:

            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS,
                     "user_count": 0}
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
        qid = frappe.get_list(
            "User",
            fields=[
                FIELD_NAME_AS_ID,
                FULL_NAME_ALIAS,
                "mobile_no as mobile_no",
            ],
            filters={"email": ["like", api_key]},
        )
        if response.status_code == 200:
            result_data = json.loads(response.text)
            result_data["refresh_token"] = "XXXXXXX"
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return Response(
                json.dumps({"data": result}),
                status=200,
                mimetype=APPLICATION_JSON,
            )

        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def get_user_name(user_email=None, mobile_phone=None):
    """to get username from useremail and mobile phone"""
    if mobile_phone is not None:
        user_details = frappe.get_list(
            "User",
            filters={"mobile_no": mobile_phone},
            fields=["name", "enabled"]
        )
    elif user_email is not None:
        user_details = frappe.get_list(
            "User", filters={"email": user_email}, fields=["name", "enabled"]
        )
    else:
        return Response(
            json.dumps({"data": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
            status=404,
            mimetype=APPLICATION_JSON,
        )

    if len(user_details) >= 1:
        return Response(
            json.dumps({"data": user_details, "user_count": 0}),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    else:
        return Response(
            json.dumps({"data": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
            status=404,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def check_user_name(user_email=None, mobile_phone=None):
    """to check the username from useremail and mobile phone"""
    user_details_email = []
    user_details_mobile = []

    if user_email is not None:
        user_details_email = frappe.get_list(
            "User", filters={"email": user_email}, fields=["name", "enabled"]
        )
    if mobile_phone is not None:
        user_details_mobile = frappe.get_list(
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
    if check_user_name(user_email=email, mobile_phone=mobile_no) > 0:
        return Response(
            json.dumps(
                {"message": "User already exists",
                 "user_count": 1}
                ),
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
        return g_generate_reset_password_key(
            email, send_email=True, password_expired=False, mobile=mobile_no
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
                json.dumps(formatted_message),
                status=400, mimetype=APPLICATION_JSON
            )

        return Response(
            json.dumps(
                {"message": error_message,
                 "user_count": 0}
                ),
            status=500,
            mimetype=APPLICATION_JSON,
        )


# to generate reset key for new user
@frappe.whitelist(allow_guest=False)
def g_generate_reset_password_key(
    user,
    mobile="",
    send_email=True,
    password_expired=False,
):
    """to generate a reset password key"""

    if mobile == "":
        return Response(
            json.dumps(
                {"message": "Mobile or Email  not found",
                 "user_count": 0}
                ),
            status=404,
            mimetype=APPLICATION_JSON,
        )
    try:
        if len(
        frappe.get_all(
            "User",
            filters={"name": user, "mobile_no": mobile}
        )
        ) < 1:
            return Response(
            json.dumps({
                "status": "error",
                "message": "User not found"
            }),
            mimetype="application/json"
        )

        key = str(secrets.randbelow(900000) + 100000)
        doc2 = frappe.get_doc("User", user)
        doc2.reset_password_key = sha256_hash(key)
        doc2.last_reset_password_key_generated_on = now_datetime()
        doc2.save(ignore_permissions=True)
        url = "/update-password?key=" + key
        msg = frappe.get_doc("Email Template", "gauth erpgulf")
        message = msg.response_html
        message = message.replace("xxxxxx", key)
        name = frappe.get_all(
            "User",
            fields=["full_name"],
            filters={"name": user, "mobile_no": mobile},
        )
        full_name = name[0].get("full_name")
        updated_html_content = message.replace("John Deo", full_name)
        subject = "OTP"
        if password_expired:
            url = "/update-password?key=" + key + "&password_expired=true"
        get_url(url)
        if send_email:
            send_email_oci(user, subject, updated_html_content)
        return Response(
            json.dumps(
                {
                    "reset_key": "XXXXXX",
                    "generated_time": str(now_datetime()),
                    "URL": "XXXXXXXX",
                }
            ),
            status=200,
            mimetype=APPLICATION_JSON,
        )
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def send_email_oci(recipient, subject, body_html):
    """send an email to recipient with subject"""
    sender = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "sender")
    sender_name = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS,
                                             "sender_name")
    user_smtp = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS,
                                           "user_smtp")
    password_smtp = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS,
                                               "password_smtp")
    host = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "host")
    port = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "port")
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
    except Exception as e:
        return f"Error: {e}"


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
            status_code = 200
        if email_count >= 1 and mobile_count < 1:
            response = {"message": "Email exists", "user_count": email_count}
            status_code = 200
        if mobile_count >= 1 and email_count >= 1:
            response = {
                "message": "Mobile and Email exists",
                "user_count": mobile_count,
            }
            status_code = 200
        if mobile_count < 1 and email_count < 1:
            response = {"message": "Mobile and Email does not exist",
                        "user_count": 0}
            status_code = 404
        return Response(
            json.dumps(response),
            status=status_code,
            mimetype=APPLICATION_JSON
        )

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def g_update_password(username, password):
    """to update the user password"""
    try:
        if len(frappe.get_all("User", {"email": username})) < 1:
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE}),
                status=404,
                mimetype=APPLICATION_JSON,
            )
        _update_password(username, password)
        qid = frappe.get_list(
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
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def g_delete_user(email, mobile_no):
    """to delete the user"""
    try:
        if (
            len(
                frappe.get_all(
                    "User", {"name": email,
                             "email": email,
                             "mobile_no": mobile_no}
                )
            )
            < 1
        ):
            return Response(
                json.dumps(
                    {"message": USER_NOT_FOUND_MESSAGE,
                            "user_count": 0}
                    ),
                status=404,
                mimetype=APPLICATION_JSON,
            )

        frappe.db.delete(
            "User", {"name": email, "email": email, "mobile_no": mobile_no}
        ),
        frappe.db.delete(
            "Customer",
            {"name": email, "customer_name": email, "mobile_no": mobile_no},
        )
        return json_response(
            {"message": "User successfully deleted",
             "user_count": 1}
            )
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def validate_email(email_to_validate):
    """to validate the user email"""

    blocked = False
    is_valid_email = (
        lambda email_to_validate: re.match(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email_to_validate
        )
        is not None
    )
    if not is_valid_email(email_to_validate):
        return Response(
            json.dumps(
                {"blocked": True,
                 "reason": "Email format not correct"}
                ),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    get_domain_name = lambda email_to_validate: (
        email_to_validate.split("@")[-1] if "@" in email_to_validate else None
    )
    domain_name = get_domain_name(email_to_validate)
    url = f"https://www2.istempmail.com/api/check/CirMirL3dAHELe8pKdUeG55KV3qy6weU/{domain_name}"
    payload = {}
    headers = {}

    try:
        response = requests.get(url, headers=headers, data=payload, timeout=10)
        api_response = response.json()
        blocked = api_response.get("blocked", False)

    except requests.exceptions.RequestException:
        pass

    if blocked is True:
        return Response(
            json.dumps(
                {
                    "blocked": True,
                    "reason": "Temporary email not accepted.",
                }
            ),
            status=200,
            mimetype=APPLICATION_JSON,
        )

    domain_js_path = os.path.join(
        os.path.dirname(__file__), "..", "public", "domain.js"
    )

    try:
        with open(domain_js_path, "r", encoding="utf-8") as file:
            domain_js_content = file.read()

        domains_list = json.loads(domain_js_content)

        if domain_name in domains_list:
            return json_response(
                {
                    "blocked": True,
                    "reason": "Public email not accepted",
                }
            )
        else:

            return json_response({"blocked": False})

    except Exception:
        return Response(
            json.dumps({"blocked": False}),
            status=400,
            mimetype=APPLICATION_JSON
        )


@frappe.whitelist(allow_guest=False)
def g_user_enable(username, email, mobile_no, enable_user: bool = True):
    """to Enable the  User"""
    try:
        if (
            len(
                frappe.get_all(
                    "User", {
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
                    {"message": USER_NOT_FOUND_MESSAGE,
                     "user_count": 0}
                    ),
                status=404,
                mimetype=APPLICATION_JSON,
            )

        frappe.db.set_value("User", username, "enabled", enable_user)
        return json_response(
            {
                "message": f"User successfully {'enabled' if enable_user else 'disabled'} ",
                "user_count": 1,
            }
        )

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def g_update_password_using_usertoken(password):
    """to update user password using user token"""
    try:
        username = frappe.session.user
        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps(
                    {"message": USER_NOT_FOUND_MESSAGE,
                     "user_count": 0}
                    ),
                status=404,
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
            filters={"customer_name": ["like", username]},
        )
        result = {
            "message": "Password successfully updated",
            "user_details": qid[0] if qid else {},
        }
        return Response(
            json.dumps({"data": result}), status=200, mimetype=APPLICATION_JSON
        )

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def g_update_password_using_reset_key(new_password, reset_key, username):
    """to update user password using reset key"""
    try:

        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps(
                    {"message": USER_NOT_FOUND_MESSAGE,
                            "user_count": 0}
                           ),
                status=404,
                mimetype=APPLICATION_JSON,
            )
        update_password(new_password=new_password, key=reset_key)

        if frappe.local.response.http_status_code == 410:
            return Response(
                json.dumps({"message": "Invalid or expired key"}),
                status=frappe.local.response.http_status_code,
                mimetype=APPLICATION_JSON,
            )
        if frappe.local.response.http_status_code == 400:
            return Response(
                json.dumps({"message": "Invalid or expired key"}),
                status=frappe.local.response.http_status_code,
                mimetype=APPLICATION_JSON,
            )
        frappe.local.response.http_status_code = 200
        if frappe.local.response.http_status_code == 200:
            return Response(
                json.dumps({"message": "Password Successfully updated"}),
                status=frappe.local.response.http_status_code,
                mimetype=APPLICATION_JSON,
            )

    except Exception as e:
        return Response(
            json.dumps({"message": str(e), "user_count": 0}),
            status=400,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=False)
def login_time():
    """To get the Login Details of user"""

    username = frappe.session.user
    doc = frappe.get_all(
        "User Log Details", fields=["time"], filters={"username": ["like", username]}
    )
    return doc


@frappe.whitelist(allow_guest=False)
def send_firebase_data(
    auction_id,
    notification_type,
    user_name=None,
    user_id=None,
    winner_amount=None,
    client_token="",
    topic="",
):
    """to send message to firebase"""

    url = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "url")

    if notification_type == "auction_ended":
        payload = json.dumps(
            {
                "message": {
                    "topic": auction_id,
                    "data": {
                        "notification_type": "auction_ended",
                        "auctionId": auction_id,
                    },
                }
            }
        )
    else:
        payload = json.dumps(
            {
                "message": {
                    "topic": auction_id,
                    "data": {
                        "notification_type": "winner_announcement",
                        "auctionId": auction_id,
                        "winner_name": user_id,
                        "winner_id": user_id,
                        "highest_bid_amount": "{:,.2f}".format(winner_amount),
                    },
                }
            }
        )
    headers = {
        "Authorization": "Bearer " + _get_access_token(),
        "Content-Type": APPLICATION_JSON,
    }

    requests.request("POST", url, headers=headers, data=payload, timeout=10)
    return json_response({"data": "Message sent"})


# to get access token for request to firebase
@frappe.whitelist(allow_guest=False)
def _get_access_token():
    """Retrieve a valid access token that can be used to authorize requests. FCM

    :return: Access token.
    """
    SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
    credential = service_account.Credentials.from_service_account_file(
        "dallah-fcm.json", scopes=SCOPES
    )
    request = google.auth.transport.requests.Request()
    credential.refresh(request)
    return credential.token


# to validate ip
@frappe.whitelist(allow_guest=False)
def validate_country(ip_address):
    """To validate IP address Country"""

    reader = geoip2.database.Reader("geo-ip.mmdb")
    response = reader.country(ip_address)

    return response.country.name


@frappe.whitelist(allow_guest=False)
def get_restriction_by_ip(source_ip_address):
    """Fetch restrictions by IP address."""
    return frappe.get_all(
        "Countries and IP address",
        filters={
            "parent": BACKEND_SERVER_SETTINGS,
            "countries":source_ip_address
        },
        fields=[
            "countries",
            "api_allow",
            "desk_web_user_allow",
            "desk_user_allow",
        ],
    )
    # for restriction in restrictions:
    #     country_entry = restriction.get("countries")
    #     try:
    #         # Check if it's a valid CIDR block and if the IP is within the range
    #         if "/" in country_entry:
    #             if ipaddress.ip_address(source_ip_address) in ipaddress.ip_network(country_entry):
    #                 return [restriction]
    #         else:
    #             # Treat it as a single IP address
    #             if source_ip_address == country_entry:
    #                 return [restriction]
    #     except ValueError:
    #         # Ignore invalid IP or CIDR formats in the database
    #         frappe.log_error(f"Invalid IP or CIDR format: {country_entry}", "IP Restriction Error")

    # # No matching restrictions found
    # return []


@frappe.whitelist(allow_guest=False)
def get_country_from_ip(ip_address):
    """Retrieve the country name from an IP address."""
    reader = geoip2.database.Reader("geo-ip.mmdb")
    response = reader.country(ip_address)
    return response.country.name


@frappe.whitelist(allow_guest=False)
def get_restriction_by_country(country):
    """Fetch restrictions by country."""
    return frappe.get_all(
        "Countries and IP address",
        filters={
            "parent": BACKEND_SERVER_SETTINGS,
            "countries": country,
        },
        fields=[
            "countries",
            "api_allow",
            "desk_web_user_allow",
            "desk_user_allow",
        ],
    )


@frappe.whitelist(allow_guest=False)
def handle_api_restrictions(restriction, ip_address):
    """Handle API access restrictions."""
    if restriction[0].get("api_allow") == 0:
        frappe.throw(
            "Access To this API  is not allowed " f"IP: {ip_address}",
                        frappe.PermissionError,
                    )
        return


@frappe.whitelist(allow_guest=False)
def deny_access(user_type):
    """Deny access and send an appropriate response."""
    frappe.throw(
            f"Access to this {user_type} from your location is not allowed "
            + frappe.local.request.headers.get("X-Forwarded-For")
        )
    frappe.local.response["http_status_code"] = 403
    return
    # frappe.local.response["http_status_code"] = 403


@frappe.whitelist(allow_guest=False)
def handle_non_api_restrictions(restriction):
    """Handle restrictions for non-API access."""
    user_type = frappe.get_all(
        "User",
        fields=["user_type"],
        filters={"name": frappe.session.user}
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
    try:
        source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")
        restriction = get_restriction_by_ip(source_ip_address)
        # return restriction
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
    except Exception :
        pass


@frappe.whitelist(allow_guest=False)
def get_sms_id(provider):
    """Get the SMS ID"""
    default_company = frappe.db.get_single_value("Global Defaults", "default_company")

    if provider == "twilio":
        return frappe.db.get_value(
            "Company", default_company, "custom_twilio_id"
        )

    if provider == "expertexting":
        return frappe.db.get_value(
            "Company", default_company, "custom_expertexting_id"
        )

    if provider == "vodafone":
        app = frappe.db.get_value(
            "Company", default_company, "custom_vodafone_app"
        )
        passwd = frappe.db.get_value(
            "Company", default_company, "custom_vodafone_password"
        )
        mask = frappe.db.get_value(
            "Company", default_company, "custom_vodafone_mask"
        )
        param_string = (
            "?application=" + app + "&password=" + passwd + "&mask=" + mask
        )
        return param_string



@frappe.whitelist(allow_guest=False)
def send_sms_vodafone(phone_number, message_text):
    """to send sms for vodafone"""
    try:

        phone_number = "+91" + phone_number
        url = "https://connectsms.vodafone.com.qa/SMSConnect/SendServlet"

        payload = (
            get_sms_id("vodafone")
            + "&content="
            + message_text
            + "&source=97401"
            + "&destination="
            + phone_number
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.get(
                        url + payload,
                        headers=headers
                    )
        if response.status_code in (200, 201):
            return True
        else:
            return False

    except Exception as e:
        return "Error in qr sending SMS   " + str(e)


@frappe.whitelist(allow_guest=False)
def send_sms_twilio(phone_number, otp):
    try:

        phone_number = "+91" + phone_number
        parts = get_sms_id("twilio").split(":")

        url = (
            f"https://api.twilio.com/2010-04-01/Accounts/"
            f"{parts[0]}/Messages.json"
        )
        payload = (
            f"To={phone_number}&From=phone&Body="
            f"Your%20DallahMzad%20OTP%20Verification%20code%20{otp}"
        )

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {parts[1]}",
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code in (200, 201):
            return True
        else:
            return response.text

    except Exception as e:
        return "Error in qr sending SMS   " + str(e)


@frappe.whitelist(allow_guest=False)
def get_account_balance():
    """To get the Account Balance of a user"""
    response_content = frappe.session.user
    balance = get_balance_on(party_type="Customer", party=response_content)
    result = {"balance": 0 - balance}
    return Response(json.dumps({"data": result}),
                    status=200,
                    mimetype=APPLICATION_JSON)


@frappe.whitelist(allow_guest=False)

def time():
    """To get the Unix and server time"""

    server_time = frappe.utils.now()
    unix_time = frappe.utils.get_datetime(
        frappe.utils.now_datetime()
    ).timestamp()

    api_response = {
        "data": {
            "serverTime": server_time,
            "unix_time": unix_time
        }
    }

    return api_response



@frappe.whitelist(allow_guest=False)
def send_firebase_notification(title, body, client_token="", topic=""):
    """To send Message to Firebase"""

    if client_token == "" and topic == "":
        return Response(
            json.dumps(
                {
                    "message": "Provide client token or topic for Fb message",
                    "message_sent": 0,
                }
            ),
            status=417,
            mimetype=APPLICATION_JSON,
        )
    try:
        try:
            firebase_admin.get_app()
        except ValueError:
            cred = credentials.Certificate("firebase.json")
            firebase_admin.initialize_app(cred)
        message = ""
        if client_token != "":
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                token=client_token,
            )
        if topic != "":
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                topic=topic,
            )
        return {
            "message": "Successfully sent message",
            "response": messaging.send(message),
        }
    except Exception as e:
        error_message = str(e)
        frappe.response["message"] = "Failed to send firebase message"
        frappe.response["error"] = error_message
        frappe.response["http_status_code"] = 500
        return frappe.response


@frappe.whitelist(allow_guest=False)
def firebase_subscribe_to_topic(topic, fcm_token):

    if fcm_token == "" and topic == "":
        return Response(
            json.dumps(
                {
                "message": "Provide FCM Token and topic to send a message.",
                    "message_sent": 0,
                }
            ),
            status=417,
            mimetype=APPLICATION_JSON,
        )

    try:
        try:
            firebase_admin.get_app()
        except ValueError:
            cred = credentials.Certificate("firebase.json")
            firebase_admin.initialize_app(cred)

        try:
            response = messaging.subscribe_to_topic(fcm_token, topic)
            if response.failure_count > 0:
                return Response(
                    json.dumps({"data": "Failed to Firebase topic"}),
                    status=400,
                    mimetype=APPLICATION_JSON,
                )
            else:
                return json_response(
                    {"data": "Successfully subscribed to Firebase topic"}
                )
        except Exception as e:
            return Response(
                json.dumps(
                    {
                    "data":"Error subscribing to Firebase topic."
                    }
                ),
                status=400,
                mimetype=APPLICATION_JSON,
            )

    except Exception as e:
        error_message = str(e)
        frappe.response["message"] = "Failed to send firebase message"
        frappe.response["error"] = error_message
        frappe.response["http_status_code"] = 500
        return frappe.response


@frappe.whitelist(allow_guest=False)
def make_payment_entry(amount, user, bid, reference):
    """To make a payment entry"""

    if amount == 0:
        return "Amount not correct"

    journal_entry = frappe.new_doc("Journal Entry")
    journal_entry.posting_date = frappe.utils.now()
    journal_entry.company = frappe.db.get_single_value(
        "Global Defaults", "default_company"
    )
    journal_entry.voucher_type = "Journal Entry"
    reference = (
        reference
        + "  dated:  "
        + str(now_datetime())
        + " Bid/Other document No: "
        + bid
    )
    journal_entry.remark = reference
    debit_entry = {
        "account": "1310 - Debtors - D",
        "credit": amount,
        "credit_in_account_currency": amount,
        "account_currency": "QAR",
        "reference_name": "",
        "reference_type": "",
        "cost_center": "",
        "project": "",
        "party_type": "Customer",
        "party": user,
        "is_advance": 0,
        "reference_detail_no": reference,
    }

    credit_entry = {
        "account": "QIB Account - D",
        "debit": amount,
        "debit_in_account_currency": amount,
        "account_currency": "QAR",
        "reference_name": "",
        "reference_type": "",
        "cost_center": "",
        "project": "",
        "reference_detail_no": reference,
    }

    journal_entry.append("accounts", debit_entry)
    journal_entry.append("accounts", credit_entry)

    try:
        journal_entry.save(ignore_permissions=True)
        journal_entry.submit()
        return Response(
            json.dumps({"data": "JV Successfully created ", "message": ""}),
            status=200,
            mimetype=APPLICATION_JSON,
        )
    except Exception as e:
        frappe.db.rollback()
        frappe.log_error(
            title="Payment Entry failed to JV", message=frappe.get_traceback()
        )
        frappe.flags.deferred_accounting_error = True
        return str(e)


@frappe.whitelist(allow_guest=False)
def optimize_image_content(content, content_type):
    """Optimize image content if required."""
    args = {"content": content, "content_type": content_type}
    if frappe.form_dict.max_width:
        args["max_width"] = int(frappe.form_dict.max_width)
    if frappe.form_dict.max_height:
        args["max_height"] = int(frappe.form_dict.max_height)
    return optimize_image(**args)


@frappe.whitelist(allow_guest=False)
def attach_field_to_doc(doc):
    """Attach the file to a specific field in the document."""
    attach_field = frappe.get_doc(frappe.form_dict.doctype,
                                  frappe.form_dict.docname)
    setattr(attach_field, frappe.form_dict.fieldname, doc.file_url)
    attach_field.save(ignore_permissions=True)


@frappe.whitelist(allow_guest=False)
def process_file_upload(file, ignore_permissions):
    """Handle the file upload process."""
    content = file.stream.read()
    filename = file.filename
    content_type = guess_type(filename)[0]

    if frappe.form_dict.optimize and content_type.startswith("image/"):
        content = optimize_image_content(content, content_type)

    frappe.local.uploaded_file = content
    frappe.local.uploaded_filename = filename

    doc = frappe.get_doc(
        {
            "doctype": "File",
            "attached_to_doctype": frappe.form_dict.doctype,
            "attached_to_name": frappe.form_dict.docname,
            "attached_to_field": frappe.form_dict.fieldname,
            "folder": frappe.form_dict.folder or "Home",
            "file_name": filename,
            "file_url": frappe.form_dict.fileurl,
            "is_private": cint(frappe.form_dict.is_private),
            "content": content,
        }
    ).save(ignore_permissions=ignore_permissions)

    if frappe.form_dict.fieldname:
        attach_field_to_doc(doc)

    return doc.file_url


@frappe.whitelist(allow_guest=False)
def upload_file():
    """To upload files into the Doctype"""
    _, ignore_permissions = validate_user_permissions()
    files = frappe.request.files
    file_names = []
    urls = []

    for key, file in files.items():
        file_names.append(key)
        urls.append(process_file_upload(file, ignore_permissions))
    return urls


@frappe.whitelist(allow_guest=False)
def validate_user_permissions():
    """Validate user permissions and return user and ignore_permissions."""
    if frappe.session.user == "Guest":
        if frappe.get_system_settings("allow_guests_to_upload_files"):
            return None, True
        raise frappe.PermissionError
    else:
        user = frappe.get_doc("User", frappe.session.user)
        return user, False


@frappe.whitelist(allow_guest=False)
def get_number_of_files(file_storage):
    """To get the number of total files"""
    if (hasattr(file_storage, "get_num_files") and
            callable(file_storage.get_num_files)):
        return file_storage.get_num_files()
    else:
        return 0


@frappe.whitelist(allow_guest=False)
def _get_customer_details(user_email=None, mobile_phone=None):
    """To get the customer Details"""
    if mobile_phone is not None:
        customer_details = frappe.get_list(
            "Customer",
            filters={"mobile_no": mobile_phone},
            fields=[
                NAME_AS_EMAIL,
                "enabled",
                "customer_name as full_name",
                "mobile_no as mobile_number",
            ],
        )
    elif user_email is not None:
        customer_details = frappe.get_list(
            "Customer",
            filters={"name": user_email},
            fields=[
                NAME_AS_EMAIL,
                "enabled",
                "customer_name as full_name",
                "mobile_no as mobile_number",
            ],
        )
    else:
        return Response(
            json.dumps({
                "message": "Customer not found",
                "user_count": 0
            }),
            status=404,
            mimetype=APPLICATION_JSON,
        )

    if len(customer_details) >= 1:
        return (
            customer_details[0]["email"],
            customer_details[0]["full_name"],
            customer_details[0]["mobile_number"],
        )
    else:
        return Response(
            json.dumps(
                {"message": "Customer not found",
                 "user_count": 0}
                ),
            status=404,
            mimetype=APPLICATION_JSON,
        )


@frappe.whitelist(allow_guest=True)
def send_sms_expertexting(phone_number, otp):
    """Send an SMS to given phone number"""
    try:
        phone_number = "+974" + phone_number
        url = "https://www.expertexting.com/ExptRestApi/sms/json/Message/Send"
        message_text = urllib.parse.quote(
            f"Your validation code for DallahMzad is {otp}. "
            f"رمز التحقق الخاص بك في DallahMzad هو {otp}.\n\n"
            "شكراً لك.\n\nThank You."
        )
        payload = (
            f'username={get_sms_id("expertexting")}'
            f'&from=DEFAULT'
            f'&to={phone_number}'
            f'&text={message_text}'
            f'&type=unicode'
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request(
            "POST",
            url,
            headers=headers,
            data=payload,
            timeout=10
        )

        if response.status_code in (200, 201):
            return True
        else:
            return False
    except Exception as e:
        frappe.log_error(f"Error in sending SMS: {e}")
        return False


@frappe.whitelist(allow_guest=True)
def test_redirect_url():
    """Redirectig to Url"""
    redirect_url = "https://doodles.google/search/"

    response_data = {"data": "Redirecting to here",
                     "redirect_url": redirect_url}
    return Response(
        json.dumps(response_data),
        status=303,
        mimetype="text/html; charset=utf-8"
    )


@frappe.whitelist(allow_guest=False)
def generate_random_password(length=10):
    """To generate a Random Password"""

    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choices(characters, k=length))


@frappe.whitelist(allow_guest=False)
def payment_gateway_log(reference, amount, user, bid):
    """Logging the Payment Gateway Initailization"""
    try:
        current_time = frappe.utils.now()
        frappe.get_doc(
            {
                "doctype": "payment_gateway_initiated",
                "reference": reference,
                "date_time": current_time,
                "amount": amount,
                "user": user,
                "bid": bid,
            }
        ).insert(ignore_permissions=True)
        return "Successfully logged Payment gateway initialization"
    except Exception as e:
        frappe.log_error(title="Payment logging failed",
                         message=frappe.get_traceback())
        return "Error in payment gateway log  " + str(e)


@frappe.whitelist(allow_guest=False)
def send_email_sparkpost(Subject=None, Text=None, To=None, From=None):
    """To send an Email"""
    url = frappe.db.get_single_value("Backend Server Settings",
                                     "sparkpost_url")
    if not To:
        return Response(
            json.dumps(
                {"message": "At least one valid recipient is required"}
                ),
            status=404,
            mimetype="application/json",
        )
    if not Text:
        return Response(
            json.dumps(
                {"message": "text or html needs to exist in content"}
            ),
            status=404,
            mimetype="application/json",
        )
    if not Subject:
        return Response(
            json.dumps(
                {"message": "subject is a required field"}
                ),
            status=404,
            mimetype="application/json",
        )
    if not From:
        return Response(
            json.dumps(
                {"message": "from is a required field"}
                ),
            status=404,
            mimetype="application/json",
        )
    company = frappe.get_doc("Company", "Gauth")
    api_key = company.custom_sparkpost_id
    try:
        payload = json.dumps(
            {
                "content": {"from": From, "subject": Subject, "text": Text},
                "recipients": [{"address": To}],
            }
        )
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        response = requests.request(
            "POST",
            url, headers=headers,
            data=payload,
            timeout=10
        )

        if response.status_code == 200:
            return Response(response.text,
                            status=200,
                            mimetype="application/json")
        else:

            return Response(
                response.text,
                status=response.status_code,
                mimetype="application/json"
            )

    except Exception as e:

        return Response(
            json.dumps(
                {"message": str(e)}),
            status=500, mimetype="application/json"
        )


@frappe.whitelist(allow_guest=False)
def enable_api_call(*args, **kwargs):
    settings = frappe.get_single("Backend Server Settings")
    if settings.enable_api_logs == 0:
        return

    try:
        doc = frappe.get_doc({
        "doctype": "API Log",
        "api_url": frappe.local.request.path,
        "user_session": frappe.session.user,
        "method": frappe.local.request.method,
        "input_parameters": json.dumps(
            frappe.local.form_dict if frappe.local.form_dict else ""
        ),
        "response": json.dumps(frappe.local.response) if hasattr(
            frappe.local, 'response'
        ) else "",
        "status": frappe.local.response.get('http_status_code', 200) if hasattr(
            frappe.local, 'response'
        ) else 500,
        "time": frappe.utils.now()
    })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
        doc.save()
        return doc
    except Exception as e:
        frappe.log_error(message=str(e), title="API Log Error")


@frappe.whitelist(allow_guest=True)
def log_request_source(*args, **kwargs):
    try:

        source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")
        if not source_ip_address:
            frappe.throw("Unable to retrieve the IP address from headers.")
        reader = geoip2.database.Reader("geo-ip.mmdb")
        response = reader.country(source_ip_address)
        user_country = response.country.name
        return source_ip_address
    except Exception as e:
        frappe.throw(f"Unable to determine the country: {str(e)}")


@frappe.whitelist(allow_guest=False)
def get_restriction_by_ip_1(source_ip_address):
    """Fetch restrictions by IP address or CIDR block."""
    # Fetch all entries in the "Countries and IP address" Doctype
    # source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")
    restrictions = frappe.get_all(
        "Countries and IP address",
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
                f"Invalid IP or CIDR format: {country_entry}",
                "IP Restriction Error")

    # No matching restrictions found
    return []


# API for encrypted user token
@frappe.whitelist(allow_guest=False)
def test_generate_token_encrypt_for_user_2fa(encrypted_key):
    """to generate a usertoken using encrypted key"""
    try:
        try:

            _, decrypted_key = decrypt_2fa_key(encrypted_key)

            api_key, api_secret, app_key = decrypted_key.split("::")

        except ValueError:
            return Response(
                json.dumps(
                    {"message": "2FA token expired",
                     "user_count": 0}
                    ),
                status=401,
                mimetype=APPLICATION_JSON,
            )

        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception as e:
            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS,
                     "user_count": 0}
                    ),
                status=401,
                mimetype=APPLICATION_JSON,
            )

        client_id_value, client_secret_value = get_oauth_client(app_key)

        if client_id_value is None:

            return Response(
                json.dumps(
                    {"message": INVALID_SECURITY_PARAMETERS,
                     "user_count": 0}
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
        qid = frappe.get_list(
            "User",
            fields=[
                FIELD_NAME_AS_ID,
                FULL_NAME_ALIAS,
                "mobile_no as mobile_no",
            ],
            filters={"email": ["like", api_key]},
        )
        if response.status_code == 200:
            result_data = json.loads(response.text)
            result_data["refresh_token"] = "XXXXXXX"
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return Response(
                json.dumps({"data": result}),
                status=200,
                mimetype=APPLICATION_JSON,
            )

        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype=APPLICATION_JSON,
        )
