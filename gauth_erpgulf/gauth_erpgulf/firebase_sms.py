"""
This module contains backend server logic for gauth_erpgulf.
"""

import json
import urllib.parse
from mimetypes import guess_type
import firebase_admin
import frappe
import requests
from frappe.utils.image import optimize_image
from werkzeug.wrappers import Response
import google.auth.transport.requests
from frappe.utils import now_datetime, cint
from firebase_admin import credentials, messaging
from google.oauth2 import service_account
from erpnext.accounts.utils import get_balance_on
from gauth_erpgulf.gauth_erpgulf.backend_server import (
    get_backend_server_settings,
    generate_error_response,
    generate_success_response,
)

CUSTOMER_NOT_FOUND = "Customer not found"
ERROR_IN_QR_SMS = "Error in qr sending SMS   "
APPLICATION_JSON = "application/json"
STATUS_500 = 500
STATUS_200 = 200
ERROR = "An unexpected error occured"
COMPANY = "Company"
NAME_AS_EMAIL = "name as email"
STATUS = 404
APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded"


@frappe.whitelist(allow_guest=True)
def test_redirect_url():
    """Redirectig to Url"""
    redirect_url = "https://doodles.google/search/"

    response_data = {"data": "Redirecting here", "redirect_url": redirect_url}
    frappe.local.response = {
        "data" : response_data,
        "http_status_code" : 303
    }
    return Response(
        json.dumps(response_data), status=303, mimetype="text/html; charset=utf-8"
    )


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
        message = "Successfully logged Payment gateway initialization"
        frappe.local.response = {
            "message" : message,
            "http_status_code" : 303
    }
        return generate_success_response(message,STATUS_200)
    except ValueError as ve:
        message = "Error in payment gateway log  " + str(ve)
        frappe.local.response = {
            "message" : message,
            "http_status_code" : STATUS_500
    }
        frappe.log_error(title="Payment logging failed", message=frappe.get_traceback())
        return generate_error_response(message,None,STATUS_500)


@frappe.whitelist(allow_guest=False)
def send_email_sparkpost(subject=None, text=None, to=None, From=None):
    """To send an Email"""
    settings = get_backend_server_settings("sparkpost_url")
    url = settings["sparkpost_url"]
    if not to:
        frappe.local.response = {
            "message" : "At least one valid recipient is needed",
            "http_status_code" : STATUS
    }
        return generate_error_response("At least one valid recipient is needed",None,STATUS)
    if not text:
        frappe.local.response = {
            "message" : "text or html needs to exist in content",
            "http_status_code" : STATUS
    }
        return generate_error_response("text or html needs to exist in content",None,STATUS)
    if not subject:
        frappe.local.response = {
            "message" : "subject is a required field",
            "http_status_code" : STATUS
    }
        return generate_error_response("subject is a required field",None,STATUS)
    if not From:
        frappe.local.response = {
            "message" : "from is a required field",
            "http_status_code" : STATUS
    }
        return generate_error_response("from is a required field",None,STATUS)
    company = frappe.get_doc(COMPANY, "Gauth")
    api_key = company.custom_sparkpost_id
    try:
        payload = json.dumps(
            {
                "content": {"from": From, "subject": subject, "text": text},
                "recipients": [{"address": to}],
            }
        )
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": APPLICATION_JSON,
        }

        response = requests.request(
            "POST", url, headers=headers, data=payload, timeout=10
        )

        if response.status_code == STATUS_200:
            frappe.local.response = {
            "message" : response.text,
            "http_status_code" : STATUS_200
    }
            return generate_success_response(response.text, status=STATUS_200)

        else:
            frappe.local.response = {
            "message" : response.text,
            "http_status_code" : response.status_code
    }
            return generate_error_response(response.text,None,response.status_code)
    except ValueError as ve:
        frappe.local.response = {
            "message" : str(ve),
            "http_status_code" : STATUS_500
    }
        return generate_error_response(ERROR, error=str(ve), status=STATUS_500)


@frappe.whitelist(allow_guest=False)
def get_account_balance():
    """To get the Account Balance of a user"""
    response_content = frappe.session.user
    balance = get_balance_on(party_type="Customer", party=response_content)
    result = {"balance": 0 - balance}
    frappe.local.response = {
            "message" : result,
            "http_status_code" : STATUS_200
    }
    return generate_success_response(result, status=STATUS_200)


@frappe.whitelist(allow_guest=False)
def time():
    """To get the Unix and server time"""

    server_time = frappe.utils.now()
    unix_time = frappe.utils.get_datetime(frappe.utils.now_datetime()).timestamp()

    api_response = {"data": {"serverTime": server_time, "unix_time": unix_time}}
    frappe.local.response = {
            "message" : api_response,
            "http_status_code" : STATUS_200
    }
    return generate_success_response(api_response, status=STATUS_200)


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
        "account": "1110 - Cash - G",
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
        "account": "1110 - Cash - G",
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
        result = {"data": "Successfully created ", "message": ""}
        frappe.local.response = {
            "message" : result,
            "http_status_code" : STATUS_200
    }
        return generate_success_response(result, status=STATUS_200)

    except ValueError as ve:
        frappe.db.rollback()
        frappe.log_error(
            title="Payment Entry failed to JV", message=frappe.get_traceback()
        )
        frappe.flags.deferred_accounting_error = True
        frappe.local.response = {
            "message" : str(ve),
            "http_status_code" : STATUS_500
    }
        return generate_error_response(ERROR, str(ve) ,STATUS_500)


@frappe.whitelist(allow_guest=False)
def send_firebase_data(
    auction_id,
    notification_type,
    user_id=None,
    winner_amount=None,
):
    """Send a message to Firebase"""
    settings = get_backend_server_settings("url")
    url = settings["url"]


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
                        "highest_bid_amount": f"{winner_amount:.2f}",
                    },
                }
            }
        )
    headers = {
        "Authorization": "Bearer " + _get_access_token(),
        "Content-Type": APPLICATION_JSON,
    }

    requests.request("POST", url, headers=headers, data=payload, timeout=10)
    frappe.local.response = {
            "data" : "Meassage Sent !",
            "http_status_code" : STATUS_200
        }
    return generate_success_response("Message Sent !",STATUS_200)


@frappe.whitelist(allow_guest=False)
def send_firebase_notification(title, body, client_token="", topic=""):
    """To send Message to Firebase"""

    if client_token == "" and topic == "":
        frappe.local.response = {
            "message" : "Provide client token or topic for Fb message",
            "http_status_code" : 417
        }
        return generate_error_response("Provide client token or topic for Fb message",None,417)
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
            result = {
            "message": "Successfully sent message",
            "response": messaging.send(message),
        }
            frappe.local.response = {
            "data" : result,
            "http_status_code" : STATUS_200
        }
        return generate_success_response(json.dumps(result),STATUS_200)
    except ValueError as ve:
        error_message = str(ve)
        frappe.response["message"] = "Failed to send firebase message"
        frappe.response["error"] = error_message
        frappe.response["http_status_code"] = STATUS_500
        result = frappe.response
        frappe.local.response = {
            "data" : result,
            "http_status_code" : STATUS_500
        }
        return generate_error_response(json.dumps(result),None,STATUS_500)


@frappe.whitelist(allow_guest=False)
def firebase_subscribe_to_topic(topic, fcm_token):
    """Subscribes an FCM token to a Firebase topic."""
    if not fcm_token or not topic:
        frappe.local.response = {
            "data" : "Provide FCM Token and topic to send message.",
            "message_sent": 0,
            "http_status_code" : 417
        }
        return generate_error_response("Provide FCM Token and topic to send message.",None,417)

    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate("firebase.json")
            firebase_admin.initialize_app(cred)

        response = messaging.subscribe_to_topic([fcm_token], topic)

        if response.failure_count > 0:
            frappe.local.response = {
            "data" : "Failed to subscribe Firebase topic",
            "http_status_code" : 400
        }
            return generate_error_response("Failed to subscribe Firebase topic",None,400)
        else:
            frappe.local.response = {
            "message" : "Successfully subscribed!",
            "http_status_code" : STATUS_200
        }
            return generate_success_response("Successfully subscribed!",STATUS_200)

    except ValueError as ve:
        error_message = str(ve)
        frappe.local.response = {
            "message" : "Error subscribing to Firebase topic.",
            "error" : error_message,
            "http_status_code" : STATUS_500
        }
        return generate_error_response(
            "Error subscribing to Firebase topic.",
            error=error_message,
            status=STATUS_500,
        )


@frappe.whitelist(allow_guest=False)
def get_sms_id(provider):
    """Get the SMS ID"""
    default_company = frappe.db.get_single_value("Global Defaults", "default_company")

    if provider == "twilio":
        result = frappe.db.get_value(COMPANY, default_company, "custom_twilio_id")
        return result
    if provider == "expertexting":
        result = frappe.db.get_value(COMPANY, default_company, "custom_expertexting_id")
        return result

    if provider == "vodafone":
        app = frappe.db.get_value(COMPANY, default_company, "custom_vodafone_app")
        passwd = frappe.db.get_value(
            COMPANY, default_company, "custom_vodafone_password"
        )
        mask = frappe.db.get_value(COMPANY, default_company, "custom_vodafone_mask")
        param_string = f"?application={app}&password={passwd}&mask={mask}"
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
        headers = {"Content-Type": APPLICATION_FORM_URLENCODED}
        response = requests.get(url + payload, headers=headers, timeout=10)
        if response.status_code in (STATUS_200, 201):
            frappe.local.response = {
                "message" : True,
                "http_status_code" : response.status_code
        }
            return generate_success_response("True",response.status_code)
        else:
            frappe.local.response = {
                "message" : False,
                "http_status_code" : response.status_code
            }
            return generate_error_response("False",None,response.status_code)

    except ValueError as ve:
        frappe.local.response = {
            "message" : ERROR_IN_QR_SMS + str(ve),
            "http_status_code" : response.status_code
        }
        return generate_error_response(ERROR_IN_QR_SMS,str(ve),response.status_code)


@frappe.whitelist(allow_guest=False)
def send_sms_twilio(phone_number, otp):
    """Sends an SMS using Twilio API."""
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
            "Content-Type": APPLICATION_FORM_URLENCODED,
            "Authorization": f"Basic {parts[1]}",
        }

        response = requests.request(
            "POST", url, headers=headers, data=payload, timeout=10
        )
        if response.status_code in (STATUS_200, 201):
            frappe.local.response = {
                "message" : True,
                "http_status_code" : response.status_code
            }
            return generate_success_response(True,response.status_code)
        else:
            result = response.text
            frappe.local.response = {
                "message" : result,
                "http_status_code" :STATUS_500
            }
            return generate_error_response(result,None,STATUS_500)
    except ValueError as ve:
        return generate_error_response(ERROR_IN_QR_SMS,str(ve),STATUS_500)


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
    if hasattr(file_storage, "get_num_files") and callable(file_storage.get_num_files):
        return file_storage.get_num_files()
    else:
        return 0


@frappe.whitelist(allow_guest=False)
def get_customer_details(user_email=None, mobile_phone=None):
    """To get the customer Details"""
    if mobile_phone is not None:
        customer_details = frappe.get_all(
            "Customer",
            filters={"mobile_no": mobile_phone},
            fields=[
                NAME_AS_EMAIL,
                "customer_name as full_name",
                "mobile_no as mobile_number",
            ],
        )
    elif user_email is not None:
        customer_details = frappe.get_all(
            "Customer",
            filters={"name": user_email},
            fields=[
                NAME_AS_EMAIL,
                "customer_name as full_name",
                "mobile_no as mobile_number",
            ],
        )
    else:
        frappe.local.response = {
            "message": CUSTOMER_NOT_FOUND,
            "user_count": 0,
            "http_status_code" : STATUS
        }
        return generate_error_response(CUSTOMER_NOT_FOUND,None,STATUS)

    if len(customer_details) >= 1:
        result = [
                customer_details[0].get("email"),
                customer_details[0].get("full_name"),
                customer_details[0].get("mobile_number"),
            ]
        frappe.local.response = {
            "message" : result,
            "http_status_code" :STATUS_200
        }
        return generate_success_response(result, STATUS_200)
    else:
        frappe.local.response = {
            "message": CUSTOMER_NOT_FOUND,
            "user_count": 0,
            "http_status_code" : STATUS
        }
        return generate_error_response(CUSTOMER_NOT_FOUND,None,STATUS)


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
            f"&from=DEFAULT"
            f"&to={phone_number}"
            f"&text={message_text}"
            f"&type=unicode"
        )
        headers = {"Content-Type": APPLICATION_FORM_URLENCODED}

        response = requests.request(
            "POST", url, headers=headers, data=payload, timeout=10
        )
        return response

        if response.status_code in (STATUS_200, 201):
            frappe.local.response = {
                "message" : True,
                "http_status_code" : response.status_code
        }
            return generate_success_response(True,response.status_code)
        else:
            frappe.local.response = {
                "message" : False,
                "http_status_code" : response.status_code
        }
            return generate_error_response(False,None,response.status_code)
    except ValueError as ve:
        frappe.local.response = {
            "message" : ERROR_IN_QR_SMS + str(ve),
            "http_status_code" : STATUS_500
        }
        frappe.log_error(f"Error in sending SMS: {ve}")
        return generate_error_response(False,None,response.status_code)


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
        frappe.local.response = {
            "data" : urls,
            "http_status_code" : STATUS_200
        }
    return generate_success_response(urls,STATUS_200)


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
    attach_field = frappe.get_doc(frappe.form_dict.doctype, frappe.form_dict.docname)
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


# to get access token for request to firebase
@frappe.whitelist(allow_guest=False)
def _get_access_token():
    """Retrieve a valid access token it can be used to authorize requests.FCM
    :return: Access token.
    """
    # sco_pes= ["https://www.googleapis.com/auth/cloud-platform"]
    # credential = service_account.Credentials.from_service_account_file(
    #     frappe.local.site + "/private/files/gauth-erpgulf.json", scopes=sco_pes
    # )
    sco_pes = ["https://www.googleapis.com/auth/firebase.messaging"]
    credential = service_account.Credentials.from_service_account_file(
        "dallah-fcm.json", scopes=sco_pes
    )
    request = google.auth.transport.requests.Request()
    credential.refresh(request)
    frappe.local.response = {
            "message" : credential.token,
            "http_status_code" : STATUS_200
    }
    return generate_success_response(credential.token,STATUS_200)

