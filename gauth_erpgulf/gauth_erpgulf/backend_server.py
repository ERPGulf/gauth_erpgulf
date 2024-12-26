"""
This module generates a secure token for the application.

Args:
    api_key (str): The API key provided by the client.
    api_secret (str): The API secret provided by the client.
    app_key (str): The application key to decode.

Returns:
    Response: A JSON response indicating success or failure.
"""

import random
import base64
import json
import os
from email.utils import formataddr
from email.message import EmailMessage
import smtplib
import ssl
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
from frappe.core.doctype.user.user import update_password as _update_password_reset_key
from frappe.utils.password import update_password as _update_password
from frappe.utils import get_url
import pyotp
import requests
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


def xor_encrypt_decrypt(text, key):
    """Encrypt or decrypt text using XOR operation."""
    return "".join(
        chr(ord(c) ^ ord(k)) for c, k in zip(text, key * (len(text) // len(key) + 1))
    )


def json_response(data, status=200):
    """Return a standardized JSON response."""
    return Response(json.dumps(data), status=status, mimetype="application/json")


def generate_totp():
    """Generate TOTP token using 2FA secret."""
    secret = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "2fa_secret_key")
    totp = pyotp.TOTP(secret, interval=60)
    return totp.now()


def get_oauth_client(app_key):
    """Fetch client_id and client_secret for an OAuth client."""
    client_id, client_secret, _ = frappe.db.get_value(
        OAUTH_CLIENT,
        {"app_name": app_key},
        ["client_id", "client_secret", "user"],
    )
    if not client_id:
        raise frappe.ValidationError(_("Security Parameters are not valid"))
    return client_id, client_secret


# api for master token
@frappe.whitelist(allow_guest=True)
def generate_token_secure(api_key, api_secret, app_key):
    """
    Generates a secure token using the provided API credentials.

    Args:
        api_key (str): The API key provided by the service.
        api_secret (str): The API secret associated with the API key.
        app_key (str): An application-specific key or identifier.

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
                        "message": "Security Parameters are not valid",
                        "error": str(decode_error),
                        "user_count": 0,
                    }
                ),
                status=401,
                mimetype="application/json",
            )
        try:
            client_id_value, client_secret_value = get_oauth_client(app_key)
        except Exception as e:
            return Response(
                json.dumps({"message": "An unexpected error occured", "error": str(e)}),
                status=500,
                mimetype="application/json",
            )

        if client_id_value is None:
            # return app_key
            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
            )

        client_id = client_id_value  # Replace with your OAuth client ID
        client_secret = client_secret_value  # Replace with your OAuth client secret
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
                mimetype="application/json",
            )

        if response.status_code == 200:
            try:
                result_data = response.json()
                result_data["refresh_token"] = "XXXXXXX"
            except json.JSONDecodeError as json_error:
                return Response(
                    json.dumps(
                        {"message": "Invalid JSON response", "error": str(json_error)}
                    ),
                    status=500,
                    mimetype="application/json",
                )

            return Response(
                json.dumps({"data": result_data}),
                status=200,
                mimetype="application/json",
            )

        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


# Api for user token
@frappe.whitelist(allow_guest=False)
def generate_token_secure_for_users(username, password, app_key):
    """
    Generate a secure token for user authentication.
    Args:
        username (str): The username of the user.
        password (str): The password of the user.
        app_key (str): The application key for token generation.

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
                mimetype="application/json",
            )
        client_id_value, client_secret_value = get_oauth_client(app_key)
        if client_id_value is None:
            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
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
                json.dumps({"data": result}), status=200, mimetype="application/json"
            )
        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
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
                mimetype="application/json",
            )
        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception as e:
            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
            )
        client_id, client_secret = get_oauth_client(app_key)
        if client_id is None:
            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
            )
        url = frappe.local.conf.host_name + OAUTH_TOKEN_URL
        payload = {
            "username": api_key,
            "password": api_secret,
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        files = []
        headers = {"Content-Type": "application/json"}
        response = requests.request("POST", url, data=payload, files=files)
        if response.status_code == 200:
            result_data = json_response(response)
            return Response(
                json.dumps({"data": result_data}),
                status=200,
                mimetype="application/json",
            )
        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def test_encryption_xor(text_for_encryption, key):
    result = "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(
            text_for_encryption, key * (len(text_for_encryption) // len(key) + 1)
        )
    )
    return base64.b64encode(result.encode()).decode()


@frappe.whitelist(allow_guest=False)
def test_decryption_xor(text_for_decryption, key):
    encrypted = base64.b64decode(text_for_decryption).decode()  # Decode Base64
    return "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(encrypted, key * (len(encrypted) // len(key) + 1))
    )


@frappe.whitelist(allow_guest=False)
def test_generate_2fa():

    with open("io.claudion.com/api_encr.en", "r", encoding="utf-8") as file:
        secret = file.read().strip()
    totp = pyotp.TOTP(secret, interval=60)
    current_totp = totp.now()
    return current_totp


# Api for encrypt details used for token
@frappe.whitelist(allow_guest=True)
def test_generate_token_encrypt(text_for_encryption):
    current_totp = generate_totp()
    result = xor_encrypt_decrypt(text_for_encryption, current_totp)
    return base64.b64encode(result.encode()).decode()


# Api for encrypt user details
@frappe.whitelist(allow_guest=False)
def test_generate_token_encrypt_for_user(text_for_encryption):
    current_totp = generate_totp()
    result = xor_encrypt_decrypt(text_for_encryption, current_totp)
    return base64.b64encode(result.encode()).decode()


# API for encrypted user token
@frappe.whitelist(allow_guest=False)
def generate_token_encrypt_for_user(encrypted_key):
    try:
        try:

            _, decrypted_key = decrypt_2fa_key(encrypted_key)

            api_key, api_secret, app_key = decrypted_key.split("::")

        except ValueError:
            return Response(
                json.dumps({"message": "2FA token expired", "user_count": 0}),
                status=401,
                mimetype="application/json",
            )

        try:
            app_key = base64.b64decode(app_key).decode("utf-8")
        except Exception as e:
            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
            )

        client_id_value, client_secret_value, _ = get_oauth_client(app_key)

        if client_id_value is None:

            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
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
        headers = {"Content-Type": "application/json"}
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
            result_data = response.json()
            result_data["refresh_token"] = "XXXXXXX"
            result = {
                "token": result_data,
                "user": qid[0] if qid else {},
            }
            return Response(
                json.dumps({"data": result}),
                status=200,
                mimetype="application/json",
            )

        else:
            frappe.local.response.http_status_code = 401
            return json.loads(response.text)

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def get_user_name(user_email=None, mobile_phone=None):
    if mobile_phone is not None:
        user_details = frappe.get_list(
            "User", filters={"mobile_no": mobile_phone}, fields=["name", "enabled"]
        )
    elif user_email is not None:
        user_details = frappe.get_list(
            "User", filters={"email": user_email}, fields=["name", "enabled"]
        )
    else:
        return Response(
            json.dumps({"data": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
            status=404,
            mimetype="application/json",
        )

    if len(user_details) >= 1:
        return Response(
            json.dumps({"data": user_details, "user_count": 0}),
            status=200,
            mimetype="application/json",
        )

    else:
        return Response(
            json.dumps({"data": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
            status=404,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def check_user_name(user_email=None, mobile_phone=None, user_name=None):
    user_details_email = []
    user_details_mobile = []

    if user_email is not None:
        user_details_email = frappe.get_list(
            "User", filters={"email": user_email}, fields=["name", "enabled"]
        )
    if mobile_phone is not None:
        user_details_mobile = frappe.get_list(
            "User", filters={"mobile_no": mobile_phone}, fields=["name", "enabled"]
        )

    if len(user_details_email) >= 1 or len(user_details_mobile) >= 1:
        return 1
    else:
        return 0


@frappe.whitelist(allow_guest=False)
def g_create_user(full_name, mobile_no, email, password=None, role="Customer"):
    if (
        check_user_name(user_email=email, mobile_phone=mobile_no, user_name=full_name)
        > 0
    ):
        return Response(
            json.dumps({"message": "User already exists", "user_count": 1}),
            status=409,
            mimetype="application/json",
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

        # Create Customer document
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

        # Generate reset password key
        return g_generate_reset_password_key(
            email, send_email=True, password_expired=False, mobile=mobile_no
        )
    except ValueError as ve:
        return Response(
            json.dumps({"message": str(ve), "user_count": 0}),
            status=400,
            mimetype="application/json",
        )

    except Exception as e:
        error_message = str(e)

        if "common password" in error_message:
            formatted_message = {"message": {"password": error_message}}
            return Response(
                json.dumps(formatted_message), status=400, mimetype="application/json"
            )

        return Response(
            json.dumps({"message": error_message, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


# to generate reset key for new user
@frappe.whitelist(allow_guest=False)
def g_generate_reset_password_key(
    user,
    mobile="",
    send_email=True,
    password_expired=False,
):

    if mobile == "":
        return Response(
            json.dumps({"message": "Mobile or Email  not found", "user_count": 0}),
            status=404,
            mimetype="application/json",
        )
    try:
        if len(frappe.get_all("User", filters={"name": user, "mobile_no": mobile})) < 1:
            return Response(
                json.dumps(
                    {"message": "Email or Mobile number not found", "user_count": 0}
                ),
                status=404,
                mimetype="application/json",
            )

        key = str(random.randint(100000, 999999))
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
        link = get_url(url)
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
            mimetype="application/json",
        )
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


# to send email to validate otp
@frappe.whitelist(allow_guest=False)
def send_email_oci(recipient, subject, body_html):
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


# to check if email,mobile already exists
@frappe.whitelist(allow_guest=False)
def is_user_available(user_email=None, mobile_phone=None):
    response = ""
    status_code = 0
    try:
        if mobile_phone is not None:
            mobile_count = len(frappe.get_all("User", {"mobile_no": mobile_phone}))
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
            response = {"message": "Mobile and Email does not exist", "user_count": 0}
            status_code = 404
        return Response(
            json.dumps(response), status=status_code, mimetype="application/json"
        )

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


# update user password
@frappe.whitelist(allow_guest=False)
def g_update_password(username, password):
    try:
        if len(frappe.get_all("User", {"email": username})) < 1:
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE}),
                status=404,
                mimetype="application/json",
            )
        # frappe api to update password
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
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def g_delete_user(email, mobile_no):
    try:
        if (
            len(
                frappe.get_all(
                    "User", {"name": email, "email": email, "mobile_no": mobile_no}
                )
            )
            < 1
        ):
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
                status=404,
                mimetype="application/json",
            )

        frappe.db.delete(
            "User", {"name": email, "email": email, "mobile_no": mobile_no}
        ),
        frappe.db.delete(
            "Customer",
            {"name": email, "customer_name": email, "mobile_no": mobile_no},
        )
        return json_response({"message": "User successfully deleted", "user_count": 1})
    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def validate_email(email_to_validate):

    blocked = False
    # check email in correct format or not
    is_valid_email = (
        lambda email_to_validate: re.match(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email_to_validate
        )
        is not None
    )
    if not is_valid_email(email_to_validate):
        return Response(
            json.dumps({"blocked": True, "reason": "Email format not correct"}),
            status=200,
            mimetype="application/json",
        )

    get_domain_name = lambda email_to_validate: (
        email_to_validate.split("@")[-1] if "@" in email_to_validate else None
    )
    domain_name = get_domain_name(email_to_validate)

    url = f"https://www2.istempmail.com/api/check/CirMirL3dAHELe8pKdUeG55KV3qy6weU/{domain_name}"
    # url = "https://www2.istempmail.com/api/check/CirMirL3dAHELe8pKdUeG55KV3qy6weU/gmail.com"
    payload = {}
    headers = {}

    try:
        response = requests.get(url, headers=headers, data=payload)
        api_response = response.json()
        blocked = api_response.get("blocked", False)

    except requests.exceptions.RequestException as e:
        pass

    if blocked is True:
        return Response(
            json.dumps(
                {
                    "blocked": True,
                    "reason": "Temporary email not accepted. Please provide your company email",
                }
            ),
            status=200,
            mimetype="application/json",
        )

    domain_js_path = os.path.join(
        os.path.dirname(__file__), "..", "public", "domain.js"
    )

    try:
        with open(domain_js_path, "r") as file:
            domain_js_content = file.read()

        domains_list = json.loads(domain_js_content)

        if domain_name in domains_list:
            return json_response(
                {
                    "blocked": True,
                    "reason": "Public email not accepted. Please provide your company email",
                }
            )
        else:

            return json_response({"blocked": False})

    except Exception as e:
        return Response(
            json.dumps({"blocked": False}), status=400, mimetype="application/json"
        )


@frappe.whitelist(allow_guest=False)
def g_user_enable(username, email, mobile_no, enable_user: bool = True):
    """to Enable the  User"""
    try:
        if (
            len(
                frappe.get_all(
                    "User", {"name": username, "email": email, "mobile_no": mobile_no}
                )
            )
            < 1
        ):
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
                status=404,
                mimetype="application/json",
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
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def g_update_password_using_usertoken(password):
    try:
        username = frappe.session.user
        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
                status=404,
                mimetype="application/json",
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
            json.dumps({"data": result}), status=200, mimetype="application/json"
        )

    except Exception as e:
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def g_update_password_using_reset_key(new_password, reset_key, username):
    try:

        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps({"message": USER_NOT_FOUND_MESSAGE, "user_count": 0}),
                status=404,
                mimetype="application/json",
            )
        _update_password_reset_key(new_password=new_password, key=reset_key)

        if frappe.local.response.http_status_code == 410:
            return Response(
                json.dumps({"message": "Invalid or expired key"}),
                status=frappe.local.response.http_status_code,
                mimetype="application/json",
            )
        if frappe.local.response.http_status_code == 400:
            return Response(
                json.dumps({"message": "Invalid or expired key"}),
                status=frappe.local.response.http_status_code,
                mimetype="application/json",
            )
        frappe.local.response.http_status_code = 200
        if frappe.local.response.http_status_code == 200:
            return Response(
                json.dumps({"message": "Password Successfully updated"}),
                status=frappe.local.response.http_status_code,
                mimetype="application/json",
            )

    except Exception as e:
        return Response(
            json.dumps({"message": str(e), "user_count": 0}),
            status=400,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=True)
def login_time():
    """To get the Login Details of user"""

    username = frappe.session.user
    doc = frappe.get_all(
        "log_in details", fields=["time"], filters={"username": ["like", username]}
    )
    return doc


@frappe.whitelist(allow_guest=True)
def send_firebase_data(
    auction_id,
    notification_type,
    user_name=None,
    user_id=None,
    winner_amount=None,
    client_token="",
    topic="",
):

    url = frappe.db.get_single_value(BACKEND_SERVER_SETTINGS, "url")

    if notification_type == "auction_ended":
        payload = json.dumps(
            {
                "message": {
                    "topic": auction_id,  # auctionId: subcriber to that auction id,
                    "data": {
                        "notification_type": "auction_ended",
                        "auctionId": auction_id,  # ////auctionId
                    },
                }
            }
        )
    else:
        # frappe.throw(str(winner_amount))
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
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    return json_response({"data": "Message sent"})


# to get access token for request to firebase
def _get_access_token():
    """Retrieve a valid access token that can be used to authorize requests. FCM

    :return: Access token.
    """
    SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
    credentials = service_account.Credentials.from_service_account_file(
        "dallah-fcm.json", scopes=SCOPES
    )
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token


# to validate ip
@frappe.whitelist(allow_guest=True)
def validate_country(ip_address):
    """To validate IP address Country"""
    import geoip2.database

    reader = geoip2.database.Reader("geo-ip.mmdb")
    response = reader.country(ip_address)

    return response.country.name


def get_restriction_by_ip(ip_address):
    """Fetch restrictions by IP address."""
    return frappe.get_all(
        "Countries and IP address",
        filters={
            "parent": BACKEND_SERVER_SETTINGS,
            "countries": ip_address,
        },
        fields=[
            "countries",
            "api_allow",
            "desk_web_user_allow",
            "desk_user_allow",
        ],
    )


def get_country_from_ip(ip_address):
    """Retrieve the country name from an IP address."""
    reader = geoip2.database.Reader("geo-ip.mmdb")
    response = reader.country(ip_address)
    return response.country.name


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


def handle_api_restrictions(restriction, ip_address):
    """Handle API access restrictions."""
    if restriction[0].get("api_allow") == 0:
        frappe.throw(
            f"Access to this API from your location is not allowed for security reasons. IP: {ip_address}",
            frappe.PermissionError,
        )
        return


def deny_access(user_type):
    """Deny access and send an appropriate response."""
    frappe.msgprint(
        f"Access to this {user_type} from your location is not allowed for security reasons. Please contact the system administrator."
    )
    frappe.local.response["http_status_code"] = 403


def handle_non_api_restrictions(restriction):
    """Handle restrictions for non-API access."""
    user_type = frappe.get_value("User", {"name": frappe.session.user}, "user_type")
    if user_type == "System User" and restriction[0].get("desk_user_allow") == 0:
        deny_access("system user")
        return

    if user_type == "Website User" and restriction[0].get("desk_web_user_allow") == 0:
        deny_access("web user")
        return


@frappe.whitelist(allow_guest=False)
def check_country_restriction(*args, **kwargs):

    try:
        source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")

        # check source_ip is listed in the table.
        restriction = get_restriction_by_ip(source_ip_address)
        if not restriction:
            user_country = get_country_from_ip(source_ip_address)
            restriction = get_restriction_by_country(user_country)
        if restriction:
            if frappe.local.request.path.startswith("/api/method/gauth_erpgulf"):
                handle_api_restrictions(restriction, source_ip_address)
                return
            else:
                handle_non_api_restrictions(restriction)
                return

    except Exception as e:
        frappe.log_error(f"Error in country restriction check: {str(e)}")


def get_sms_id(provider):
    default_company = frappe.db.get_single_value("Global Defaults", "default_company")
    if provider == "twilio":
        return frappe.db.get_value("Company", default_company, "custom_twilio_id")
    if provider == "experttexting":
        return frappe.db.get_value(
            "Company", default_company, "custom_experttexting_id"
        )
    if provider == "vodafone":
        app = frappe.db.get_value("Company", default_company, "custom_vodafone_app")
        passw = frappe.db.get_value(
            "Company", default_company, "custom_vodafone_password"
        )
        mask = frappe.db.get_value("Company", default_company, "custom_vodafone_mask")
        param_string = "?application=" + app + "&password=" + passw + "&mask=" + mask
        return param_string


@frappe.whitelist(allow_guest=True)
def send_sms_vodafone(phone_number, message_text):  # send sms through Vodafone Qatar
    try:

        phone_number = "+91" + phone_number
        url = "https://connectsms.vodafone.com.qa/SMSConnect/SendServlet"
        # message_text = urllib.parse.quote(f"Your validation code for DallahMzad is {otp} Thank You.  \n \n  رمز التحقق الخاص بك لـ DallahMzad هو {otp} شكرًا لك.")
        # payload = f'username={get_sms_id("experttexting")}&from=DEFAULT&to={phone_number}&text=Your%20validation%20code%20for%20DallahMzad%20is%20{otp}%20Thank%20You.'
        payload = (
            get_sms_id("vodafone")
            + "&content="
            + message_text
            + "&source=97401"
            + "&destination="
            + phone_number
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request("GET", url + payload, headers=headers, data="")
        # return url + payload
        if response.status_code in (200, 201):
            return True
        else:
            return False

    except Exception as e:
        return "Error in qr sending SMS   " + str(e)


@frappe.whitelist(allow_guest=True)
def send_sms_twilio(phone_number, otp):  # Send SMS OTP using twilio
    # success response = 201 created
    try:
        import requests

        phone_number = "+91" + phone_number
        parts = get_sms_id("twilio").split(":")

        url = f"https://api.twilio.com/2010-04-01/Accounts/{parts[0]}/Messages.json"
        payload = f"To={phone_number}&From=phone&Body=Your%20DallahMzad%OTP Verification code{otp}"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {parts[1]}",
        }

        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code in (200, 201):
            return True
        else:
            return response.text

        # if response.status_code  in (400,405,406,409 ):

    except Exception as e:
        return "Error in qr sending SMS   " + str(e)


@frappe.whitelist(allow_guest=True)
def get_account_balance(customer=None):
    response_content = frappe.session.user
    balance = get_balance_on(party_type="Customer", party=response_content)
    result = {"balance": 0 - balance}
    return Response(
        json.dumps({"data": result}), status=200, mimetype="application/json"
    )


@frappe.whitelist(allow_guest=True)
def time():
    server_time = frappe.utils.now()
    unix_time = frappe.utils.get_datetime(frappe.utils.now_datetime()).timestamp()
    api_response = {"data": {"serverTime": server_time, "unix_time": unix_time}}
    return api_response


@frappe.whitelist(allow_guest=True)
def send_firebase_notification(title, body, client_token="", topic=""):
    import firebase_admin
    from firebase_admin import credentials, exceptions, messaging

    if client_token == "" and topic == "":
        return Response(
            json.dumps(
                {
                    "message": "Please provide either client token or topic to send message to Firebase",
                    "message_sent": 0,
                }
            ),
            status=417,
            mimetype="application/json",
        )
    try:
        try:
            firebase_admin.get_app()
        except ValueError:
            # If not, then initialize it
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
    import firebase_admin
    from firebase_admin import credentials, messaging

    if fcm_token == "" and topic == "":
        return Response(
            json.dumps(
                {
                    "message": "Please provide FCM Token and  topic to send message to Firebase",
                    "message_sent": 0,
                }
            ),
            status=417,
            mimetype="application/json",
        )

    try:

        # Check if app already exists
        try:
            firebase_admin.get_app()
        except ValueError:
            # If not, then initialize it
            cred = credentials.Certificate("firebase.json")
            firebase_admin.initialize_app(cred)

        try:
            response = messaging.subscribe_to_topic(fcm_token, topic)
            if response.failure_count > 0:
                return Response(
                    json.dumps({"data": "Failed to subscribe to Firebase topic"}),
                    status=400,
                    mimetype="application/json",
                )
            else:
                return json_response(
                    {"data": "Successfully subscribed to Firebase topic"}
                )
        except Exception as e:
            return Response(
                json.dumps(
                    {
                        "data": "Error happened while trying to  subscribe to Firebase topic"
                    }
                ),
                status=400,
                mimetype="application/json",
            )

    except Exception as e:
        error_message = str(e)
        frappe.response["message"] = "Failed to send firebase message"
        frappe.response["error"] = error_message
        frappe.response["http_status_code"] = 500
        return frappe.response


@frappe.whitelist(allow_guest=True)
def make_payment_entry(amount, user, bid, reference):

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
        # "account": "QIB Account - D",
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
        # "account": "1310 - Debtors - D",
        "debit": amount,
        "debit_in_account_currency": amount,
        "account_currency": "QAR",
        "reference_name": "",
        "reference_type": "",
        "reference_detail_no": "",
        "cost_center": "",
        "project": "",
        "reference_detail_no": reference,
        # "party_type": "Customer",
        # "party": "mumtaz@erpgulf.com422"
    }

    # for dimension in get_accounting_dimensions():
    # 	debit_entry.update({dimension: item.get(dimension)})

    # 	credit_entry.update({dimension: item.get(dimension)})

    journal_entry.append("accounts", debit_entry)
    journal_entry.append("accounts", credit_entry)

    try:
        journal_entry.save(ignore_permissions=True)
        journal_entry.submit()
        # if submit:
        # journal_entry.submit()

        # frappe.db.commit()
        return Response(
            json.dumps({"data": "JV Successfully created ", "message": ""}),
            status=200,
            mimetype="application/json",
        )
    except Exception as e:
        frappe.db.rollback()
        frappe.log_error(
            title="Payment Entry failed to JV", message=frappe.get_traceback()
        )
        frappe.flags.deferred_accounting_error = True
        return str(e)
        # return  Response(json.dumps({"data": "There was an error in creating JV", "message": "Use token with higher privilage to enter JV" }), status=401, mimetype='application/json')


@frappe.whitelist(allow_guest=True)
def upload_file():
    user = None
    if frappe.session.user == "Guest":
        if frappe.get_system_settings("allow_guests_to_upload_files"):
            ignore_permissions = True
        else:
            raise frappe.PermissionError
    else:
        user: "User" = frappe.get_doc("User", frappe.session.user)
        ignore_permissions = False

    files = frappe.request.files
    file_names = []
    urls = []
    # filecount = 0
    # for key, file in files.items():
    #     filecount = filecount + 1
    #     file_names.append(key)

    # return file_names

    is_private = frappe.form_dict.is_private
    doctype = frappe.form_dict.doctype
    docname = frappe.form_dict.docname
    fieldname = frappe.form_dict.fieldname
    file_url = frappe.form_dict.file_url
    folder = frappe.form_dict.folder or "Home"
    method = frappe.form_dict.method
    filename = frappe.form_dict.file_name
    optimize = frappe.form_dict.optimize
    content = None
    filenumber = 0
    for key, file in files.items():
        filenumber = filenumber + 1
        file_names.append(key)
        file = files[key]
        content = file.stream.read()
        filename = file.filename

        content_type = guess_type(filename)[0]
        if optimize and content_type and content_type.startswith("image/"):
            args = {"content": content, "content_type": content_type}
            if frappe.form_dict.max_width:
                args["max_width"] = int(frappe.form_dict.max_width)
            if frappe.form_dict.max_height:
                args["max_height"] = int(frappe.form_dict.max_height)
            content = optimize_image(**args)

        frappe.local.uploaded_file = content
        frappe.local.uploaded_filename = filename

        if content is not None and (
            frappe.session.user == "Guest" or (user and not user.has_desk_access())
        ):
            filetype = guess_type(filename)[0]
            # if filetype not in ALLOWED_MIMETYPES:
            #     frappe.throw(_("You can only upload JPG, PNG, PDF, TXT or Microsoft documents."))

        if method:
            method = frappe.get_attr(method)
            is_whitelisted(method)
            return method()
        else:
            # return frappe.get_doc(
            doc = frappe.get_doc(
                {
                    "doctype": "File",
                    "attached_to_doctype": doctype,
                    "attached_to_name": docname,
                    "attached_to_field": fieldname,
                    "folder": folder,
                    "file_name": filename,
                    "file_url": file_url,
                    "is_private": cint(is_private),
                    "content": content,
                }
            ).save(ignore_permissions=ignore_permissions)
            urls.append(doc.file_url)

            if fieldname is not None:
                attach_field = frappe.get_doc(
                    doctype, docname
                )  # .save(ignore_permissions = True)
                setattr(attach_field, fieldname, doc.file_url)
                attach_field.save(ignore_permissions=True)

    return urls


def get_number_of_files(file_storage):
    # Implement your logic to count the number of files
    # Adjust this based on the actual structure of the FileStorage object
    # For example, if FileStorage has a method to get the number of files, use that

    # Example: Assuming a method called get_num_files() on FileStorage
    if hasattr(file_storage, "get_num_files") and callable(file_storage.get_num_files):
        return file_storage.get_num_files()
    else:
        return 0


@frappe.whitelist(allow_guest=False)
def _get_customer_details(user_email=None, mobile_phone=None):
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
            json.dumps({"message": "Customer not found", "user_count": 0}),
            status=404,
            mimetype="application/json",
        )

    if len(customer_details) >= 1:
        return (
            customer_details[0]["email"],
            customer_details[0]["full_name"],
            customer_details[0]["mobile_number"],
        )
    else:
        return Response(
            json.dumps({"message": "Customer not found", "user_count": 0}),
            status=404,
            mimetype="application/json",
        )
