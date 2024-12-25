"""
This module generates a secure token for the application.

Args:
    api_key (str): The API key provided by the client.
    api_secret (str): The API secret provided by the client.
    app_key (str): The application key to decode.

Returns:
    Response: A JSON response indicating success or failure.
"""

# import pikepdf
# import tempfile
# import subprocess
# import os

import random
import base64
import json
import os
import geoip2.database
import frappe
from erpnext.accounts.utils import get_balance_on, get_fiscal_year

from email.utils import formataddr
from email.message import EmailMessage
import smtplib
import ssl
import re
from frappe.utils.response import Response
import google.auth.transport.requests
from google.oauth2 import service_account
from frappe.utils import now_datetime
from frappe.utils.data import sha256_hash
import geoip2.database
from frappe.core.doctype.user.user import User
from frappe.core.doctype.user.user import update_password as _update_password_reset_key
from frappe.utils.password import update_password as _update_password
from frappe.utils import get_url
import pyotp
import requests
from werkzeug.wrappers import Response
import firebase_admin
from firebase_admin import credentials, exceptions, messaging


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
            client_id_value, client_secret_value = frappe.db.get_value(
                "OAuth Client",
                {"app_name": app_key},
                ["client_id", "client_secret"],
            )
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
        url = (
            frappe.local.conf.host_name
            + "/api/method/frappe.integrations.oauth2.get_token"
        )
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
        client_id_value, client_secret_value = frappe.db.get_value(
            "OAuth Client",
            {"app_name": app_key},
            ["client_id", "client_secret"],
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
        url = (
            frappe.local.conf.host_name
            + "/api/method/frappe.integrations.oauth2.get_token"
        )
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
                "name as id",
                "full_name as  full_name",
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
                # "time": str(now),
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

        # return {"data": "Guest"}
        response_content = {
            "data": {
                "user": frappe.session.user,
            }
        }
        return Response(
            json.dumps(response_content), status=200, mimetype="application/json"
        )
        # return frappe.session.user
    except Exception as e:
        frappe.throw(e)


# Api for refresh token
@frappe.whitelist(allow_guest=False)
def create_refresh_token(refresh_token):
    """this function creates refresh token"""
    url = (
        frappe.local.conf.host_name + "/api/method/frappe.integrations.oauth2.get_token"
    )
    payload = f"grant_type=refresh_token&refresh_token={refresh_token}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    files = []

    response = requests.post(
        url, headers=headers, data=payload, files=files, timeout=10
    )

    if response.status_code == 200:
        try:

            message_json = json.loads(response.text)

            new_message = {
                "access_token": message_json["access_token"],
                "expires_in": message_json["expires_in"],
                "token_type": message_json["token_type"],
                "scope": message_json["scope"],
            }

            return Response(
                json.dumps({"data": new_message}),
                status=200,
                mimetype="application/json",
            )
        except json.JSONDecodeError as e:
            return Response(
                json.dumps({"data": f"Error decoding JSON: {e}"}),
                status=401,
                mimetype="application/json",
            )
    else:

        return Response(
            json.dumps({"data": response.text}), status=401, mimetype="application/json"
        )


# api for decrypting encrypt key
@frappe.whitelist(allow_guest=False)
def decrypt_2FA(encrypted_key):
    """This function used for decrypting the 2FA encrypted Key"""

    secret = frappe.db.get_single_value("Backend Server Settings", "2fa_secret_key")
    totp = pyotp.TOTP(secret, interval=60)
    current_totp = totp.now()
    encrypted = base64.b64decode(encrypted_key).decode()
    return current_totp, "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(
            encrypted, current_totp * (len(encrypted) // len(current_totp) + 1)
        )
    )


# Api for encripted master token
@frappe.whitelist(allow_guest=False)
def generate_token_encrypt(encrypted_key):
    """This function creates the master token using the encrypted key"""
    try:
        try:

            _, decrypted_key = decrypt_2FA(encrypted_key)

            api_key, api_secret, app_key = decrypted_key.split("::")

        except:
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

        clientID, clientSecret, _ = frappe.db.get_value(
            "OAuth Client",
            {"app_name": app_key},
            ["client_id", "client_secret", "user"],
        )

        if clientID is None:
            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
            )

        client_id = clientID
        client_secret = clientSecret
        url = (
            frappe.local.conf.host_name
            + "/api/method/frappe.integrations.oauth2.get_token"
        )
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
            result_data = json.loads(response.text)
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
def test_Encryption_xor(text_for_encryption, key):
    result = "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(
            text_for_encryption, key * (len(text_for_encryption) // len(key) + 1)
        )
    )
    return base64.b64encode(result.encode()).decode()


@frappe.whitelist(allow_guest=False)
def test_Decryption_xor(text_for_decryption, key):
    encrypted = base64.b64decode(text_for_decryption).decode()  # Decode Base64
    return "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(encrypted, key * (len(encrypted) // len(key) + 1))
    )


@frappe.whitelist(allow_guest=False)
def test_generate_2FA():

    with open("io.claudion.com/api_encr.en", "r", encoding="utf-8") as file:
        secret = file.read().strip()
    totp = pyotp.TOTP(secret, interval=60)
    current_totp = totp.now()
    return current_totp


# Api for encrypt details used for token
@frappe.whitelist(allow_guest=True)
def test_generate_token_encrypt(text_for_encryption):

    secret = frappe.db.get_single_value("Backend Server Settings", "2fa_secret_key")
    totp = pyotp.TOTP(secret, interval=60)
    current_totp = totp.now()
    result = "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(
            text_for_encryption,
            current_totp * (len(text_for_encryption) // len(current_totp) + 1),
        )
    )
    return base64.b64encode(result.encode()).decode()


# Api for encrypt user details
@frappe.whitelist(allow_guest=False)
def test_generate_token_encrypt_for_user(text_for_encryption):

    secret = frappe.db.get_single_value("Backend Server Settings", "2fa_secret_key")
    totp = pyotp.TOTP(secret, interval=60)
    current_totp = totp.now()
    result = "".join(
        chr(ord(c) ^ ord(k))
        for c, k in zip(
            text_for_encryption,
            current_totp * (len(text_for_encryption) // len(current_totp) + 1),
        )
    )
    return base64.b64encode(result.encode()).decode()


# API for encrypted user token
@frappe.whitelist(allow_guest=False)
def generate_token_encrypt_for_user(encrypted_key):
    try:
        try:

            current_totp, decrypted_key = decrypt_2FA(encrypted_key)

            api_key, api_secret, app_key = decrypted_key.split("::")

        except:
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

        clientID, clientSecret, _ = frappe.db.get_value(
            "OAuth Client",
            {"app_name": app_key},
            ["client_id", "client_secret", "user"],
        )

        if clientID is None:

            return Response(
                json.dumps(
                    {"message": "Security Parameters are not valid", "user_count": 0}
                ),
                status=401,
                mimetype="application/json",
            )

        client_id = clientID
        client_secret = clientSecret
        url = (
            frappe.local.conf.host_name
            + "/api/method/frappe.integrations.oauth2.get_token"
        )
        payload = {
            "username": api_key,
            "password": api_secret,
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            # "grant_type": "refresh_token"
        }
        files = []
        headers = {"Content-Type": "application/json"}
        response = requests.request("POST", url, data=payload, files=files)
        qid = frappe.get_list(
            "User",
            fields=[
                "name as id",
                "full_name as  full_name",
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
                # "time": str(now),
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
            json.dumps({"data": "User not found", "user_count": 0}),
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
            json.dumps({"data": "User not found", "user_count": 0}),
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
    # if password == None:
    # password = generate_random_password(10)
    # Check if the user already exists
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
        # Create User document
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
    # doc=frappe.get_all('User', fields=["name"],filters={'name': user, 'mobile_no': mobile})
    # return doc
    from frappe.utils.data import sha256_hash

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

        # if(len(frappe.get_all('User', {'name': user}))<1):
        #     return  Response(json.dumps({"message": "Email or Mobile number not found" , "user_count": 0}), status=404, mimetype='application/json')
        # if(len(frappe.get_all('User', {'mobile_no': mobile}))<1):
        #     return  Response(json.dumps({"message": "Mobile number or Email not found" , "user_count": 0}), status=404, mimetype='application/json')
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
        # send_sms_expertexting(mobile,key)  # stop this on testing cycle as it send SMSes
        # send_sms_vodafone(mobile, urllib.parse.quote(f"Your Validation code for DallahMzad is {key} Thank You.  \n \n  رمز التحقق الخاص بك لـ DallahMzad هو {key} شكرًا لك."))
        link = get_url(url)
        if send_email:
            send_email_oci(user, subject, updated_html_content)
            # send_email_oci(user,"Claudion Account Validation Key","Please use this key to activate or reset your  account password. This key valid only for 10 minutes and for one-time use only. Your key is " + key)

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

    sender = frappe.db.get_single_value('Backend Server Settings', 'sender'),
    sender_name = frappe.db.get_single_value('Backend Server Settings', 'sender_name'),

    user_smtp = frappe.db.get_single_value('Backend Server Settings', 'user_smtp'),
    password_smtp = frappe.db.get_single_value('Backend Server Settings', 'password_smtp'),

    host = frappe.db.get_single_value('Backend Server Settings', 'host')
    port = frappe.db.get_single_value('Backend Server Settings', 'port')

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, sender))
    msg["To"] = recipient

    msg.set_content(body_html, subtype="html")
    # msg.add_alternative(body_html, subtype='html')

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
                json.dumps({"message": "User not found"}),
                status=404,
                mimetype="application/json",
            )
        # frappe api to update password
        _update_password(username, password)
        qid = frappe.get_list(
            "User",
            fields=[
                "name as id",
                "full_name as  full_name",
                "mobile_no as phone",
                "name as email",
            ],
            filters={"email": ["like", username]},
        )
        result = {
            "message": "Password successfully updated",
            "user_details": qid[0] if qid else {},
        }
        # frappe.db.commit()
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
                json.dumps({"message": "User not found", "user_count": 0}),
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
        return Response(
            json.dumps({"message": "User successfully deleted", "user_count": 1}),
            status=200,
            mimetype="application/json",
        )

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

    if blocked == True:
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
    else:
        pass

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
                        "reason": "Public email not accepted. Please provide your company email",
                    }
                ),
                status=200,
                mimetype="application/json",
            )
        else:

            return Response(
                json.dumps({"blocked": False}), status=200, mimetype="application/json"
            )

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
                json.dumps({"message": "User not found", "user_count": 0}),
                status=404,
                mimetype="application/json",
            )

        frappe.db.set_value("User", username, "enabled", enable_user)
        return Response(
            json.dumps(
                {
                    "message": f"User successfully {'enabled' if enable_user else 'disabled'} ",
                    "user_count": 1,
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


@frappe.whitelist(allow_guest=False)
def g_update_password_using_usertoken(password):
    try:
        username = frappe.session.user
        if len(frappe.get_all("User", {"name": username})) < 1:
            return Response(
                json.dumps({"message": "User not found", "user_count": 0}),
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
                # "name as email",
            ],
            filters={"customer_name": ["like", username]},
        )
        result = {
            "message": "Password successfully updated",
            "user_details": qid[0] if qid else {},
        }
        # frappe.db.commit()
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
                json.dumps({"message": "User not found", "user_count": 0}),
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
    # Sending firebase data to Android and IPhone from Frappe ERPNext

    # frappe.throw(str(_get_access_token()))
    url = url

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
    # _get_access_token to get access token for request for firebase
    headers = {
        "Authorization": "Bearer " + _get_access_token(),
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    return Response(
        json.dumps({"data": "Message sent"}), status=200, mimetype="application/json"
    )


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
def validate_country(IP_address):
    """To validate IP address Country"""
    import geoip2.database

    reader = geoip2.database.Reader("geo-ip.mmdb")
    response = reader.country(IP_address)

    return response.country.name


@frappe.whitelist(allow_guest=False)
def check_country_restriction(*args, **kwargs):

    # return kwargs.get("ip_address")
    try:
        # source_ip_address = kwargs.get("ip_address")
        source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")

        # check source_ip is listed in the table.
        restriction = frappe.get_all(
            "Countries and IP address",
            filters={
                "parent": "Backend Server Settings",
                "countries": source_ip_address,
            },
            fields=[
                "countries",
                "api_allow",
                "desk_web_user_allow",
                "desk_user_allow",
            ],
        )

        if (
            len(restriction) == 0
        ):  # if source_ip not in the table, find country of source_ip
            reader = geoip2.database.Reader("geo-ip.mmdb")
            response = reader.country(source_ip_address)
            user_country = response.country.name
            restriction = frappe.get_all(
                "Countries and IP address",
                filters={
                    "parent": "Backend Server Settings",
                    "countries": user_country,
                },
                fields=[
                    "countries",
                    "api_allow",
                    "desk_web_user_allow",
                    "desk_user_allow",
                ],
            )

        if len(restriction) > 0:
            if frappe.local.request.path.startswith("/api/method/gauth_erpgulf"):

                # check if the call is api
                if restriction[0].get("api_allow") == 0:

                    frappe.throw(
                        "Access To this API from your location is not allowed for security reasons. "
                        f"IP: {source_ip_address}",
                        frappe.PermissionError,
                    )
                    return
            else:  # as its not api , this can be either system-user or web-user
                user_type = frappe.get_all(
                    "User", fields=["user_type"], filters={"name": frappe.session.user}
                )
                if user_type[0].get("user_type") == "System User":
                    if restriction[0].get("desk_user_allow") == 0:
                        # return"system user"
                        frappe.msgprint(
                            "Access to this system-user from your location is not allowed for security reasons, please contact system administrator. "
                            + frappe.local.request.headers.get("X-Forwarded-For")
                        )
                        frappe.local.response["http_status_code"] = 403
                        # return "system user"
                if user_type[0].get("user_type") == "Website User":
                    if restriction[0].get("desk_web_user_allow") == 0:
                        # return "website user"
                        frappe.msgprint(
                            "Access to this web-user from your location is not allowed for security reasons, please contact system administrator. "
                            + frappe.local.request.headers.get("X-Forwarded-For")
                        )
                        frappe.local.response["http_status_code"] = 403
                        # return "website user"

    except:
        pass


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
def validate_country_test(IP_address):
    """To validate IP address Country"""
    import geoip2.database

    reader = geoip2.database.Reader("geo-ip.mmdb")
    response = reader.country(IP_address)

    return response.country.name


@frappe.whitelist(allow_guest=True)
def check_country_restriction_test(*args, **kwargs):

    # return kwargs.get("ip_address")
    try:
        # source_ip_address = kwargs.get("ip_address")
        source_ip_address = frappe.local.request.headers.get("X-Forwarded-For")

        # check source_ip is listed in the table.
        restriction = frappe.get_all(
            "Countries and IP address",
            filters={
                "parent": "Backend Server Settings",
                "countries": source_ip_address,
            },
            fields=[
                "countries",
                "api_allow",
                "desk_web_user_allow",
                "desk_user_allow",
            ],
        )

        if (
            len(restriction) == 0
        ):  # if source_ip not in the table, find country of source_ip
            reader = geoip2.database.Reader("geo-ip.mmdb")
            response = reader.country(source_ip_address)
            user_country = response.country.name
            restriction = frappe.get_all(
                "Countries and IP address",
                filters={
                    "parent": "Backend Server Settings",
                    "countries": user_country,
                },
                fields=[
                    "countries",
                    "api_allow",
                    "desk_web_user_allow",
                    "desk_user_allow",
                ],
            )

        if len(restriction) > 0:
            if frappe.local.request.path.startswith("/api/method/gauth_erpgulf"):

                # check if the call is api
                if restriction[0].get("api_allow") == 0:

                    frappe.throw(
                        "Access To this API from your location is not allowed for security reasons. "
                        f"IP: {source_ip_address}",
                        frappe.PermissionError,
                    )
                    return
            else:  # as its not api , this can be either system-user or web-user
                user_type = frappe.get_all(
                    "User", fields=["user_type"], filters={"name": frappe.session.user}
                )
                if user_type[0].get("user_type") == "System User":
                    if restriction[0].get("desk_user_allow") == 0:
                        # return"system user"
                        frappe.msgprint(
                            "Access to this system-user from your location is not allowed for security reasons, please contact system administrator. "
                            + frappe.local.request.headers.get("X-Forwarded-For")
                        )
                        frappe.local.response["http_status_code"] = 403
                        # return "system user"
                if user_type[0].get("user_type") == "Website User":
                    if restriction[0].get("desk_web_user_allow") == 0:
                        # return "website user"
                        frappe.msgprint(
                            "Access to this web-user from your location is not allowed for security reasons, please contact system administrator. "
                            + frappe.local.request.headers.get("X-Forwarded-For")
                        )
                        frappe.local.response["http_status_code"] = 403
                        # return "website user"

    except:
        pass
