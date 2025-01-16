"""
This module contains backend server logic for gauth_erpgulf.
"""
import json
import urllib.parse
import firebase_admin
import frappe
import requests
from frappe.utils.image import optimize_image
from werkzeug.wrappers import Response
from mimetypes import guess_type
import google.auth.transport.requests
from frappe.utils import now_datetime,cint
from firebase_admin import credentials, messaging
from google.oauth2 import service_account
from erpnext.accounts.utils import get_balance_on
from gauth_erpgulf.gauth_erpgulf.backend_server import(
    get_backend_server_settings,
    json_response,
    generate_error_response,
    generate_success_response,
    )
APPLICATION_JSON = "application/json"
STATUS_500=500
STATUS_200=200
ERROR = "An unexpected error occured"
COMPANY="Company"
NAME_AS_EMAIL = "name as email"
STATUS = 404
APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded"
   

@frappe.whitelist(allow_guest=True)
def test_redirect_url():
    """Redirectig to Url"""
    redirect_url = "https://doodles.google/search/"

    response_data = {"data": "Redirecting here", "redirect_url": redirect_url}
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
        return "Successfully logged Payment gateway initialization"
    except ValueError as ve:
        frappe.log_error(title="Payment logging failed", message=frappe.get_traceback())
        return "Error in payment gateway log  " + str(ve)
 


@frappe.whitelist(allow_guest=False)
def send_email_sparkpost(subject=None, text=None, to=None, from_=None):
    """To send an Email"""
    settings = get_backend_server_settings("sparkpost_url")
    url = settings["sparkpost_url"]
    if not to:
        return Response(
            json.dumps({"message": "At least one valid recipient is needed"}),
            status=STATUS,
            mimetype=APPLICATION_JSON,
        )
    if not text:
        return Response(
            json.dumps({"message": "text or html needs to exist in content"}),
            status=STATUS,
            mimetype=APPLICATION_JSON,
        )
    if not subject:
        return Response(
            json.dumps({"message": "subject is a required field"}),
            status=STATUS,
            mimetype=APPLICATION_JSON,
        )
    if not from_:
        return Response(
            json.dumps({"message": "from is a required field"}),
            status=STATUS,
            mimetype=APPLICATION_JSON,
        )
    company = frappe.get_doc(COMPANY, "Gauth")
    api_key = company.custom_sparkpost_id
    try:
        payload = json.dumps(
            {
                "content": {"from": from_, "subject": subject, "text": text},
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
            return generate_success_response(response.text, status=STATUS_200)

        else:

            return Response(
                response.text, status=response.status_code, mimetype=APPLICATION_JSON
            )

    except ValueError as ve:
        return generate_error_response(ERROR, error=str(ve), status=STATUS_500)


@frappe.whitelist(allow_guest=False)
def get_account_balance():
    """To get the Account Balance of a user"""
    response_content = frappe.session.user
    balance = get_balance_on(party_type="Customer", party=response_content)
    result = {"balance": 0 - balance}
    return generate_success_response(result, status=STATUS_200)
@frappe.whitelist(allow_guest=False)
def time():
    """To get the Unix and server time"""

    server_time = frappe.utils.now()
    unix_time = frappe.utils.get_datetime(frappe.utils.now_datetime()).timestamp()

    api_response = {"data": {"serverTime": server_time, "unix_time": unix_time}}
    return api_response

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
        result = {"data": "JV Successfully created ", "message": ""}
        return generate_success_response(result, status=STATUS_200)

    except ValueError as ve:
        frappe.db.rollback()
        frappe.log_error(
            title="Payment Entry failed to JV", message=frappe.get_traceback()
        )
        frappe.flags.deferred_accounting_error = True
        return str(ve)


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
    return json_response({"data": "Message sent"})


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
    except ValueError as ve:
        error_message = str(ve)
        frappe.response["message"] = "Failed to send firebase message"
        frappe.response["error"] = error_message
        frappe.response["http_status_code"] = STATUS_500
        return frappe.response


@frappe.whitelist(allow_guest=False)
def firebase_subscribe_to_topic(topic, fcm_token):
    """Subscribes an FCM token to a Firebase topic."""
    if not fcm_token or not topic:
        return Response(
            json.dumps(
                {
                    "message": "Provide FCM Token and topic to send message.",
                    "message_sent": 0,
                }
            ),
            status=417,
            mimetype=APPLICATION_JSON,
        )

    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate("firebase.json")
            firebase_admin.initialize_app(cred)

        response = messaging.subscribe_to_topic([fcm_token], topic)

        if response.failure_count > 0:
            return Response(
                json.dumps({"message": "Failed to subscribe Firebase topic"}),
                status=400,
                mimetype=APPLICATION_JSON,
            )
        else:
            return json_response({"message": "Successfully subscribed"})

    except ValueError as ve:
        error_message = str(ve)
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
        return frappe.db.get_value(COMPANY, default_company, "custom_twilio_id")

    if provider == "expertexting":
        return frappe.db.get_value(COMPANY, default_company, "custom_expertexting_id")

    if provider == "vodafone":
        app = frappe.db.get_value(COMPANY, default_company, "custom_vodafone_app")
        passwd = frappe.db.get_value(
            COMPANY, default_company, "custom_vodafone_password"
        )
        mask = frappe.db.get_value(COMPANY, default_company, "custom_vodafone_mask")
        param_string = "?application=" + app + "&password=" + passwd + "&mask=" + mask
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
            return True
        else:
            return False

    except ValueError as ve:
        return "Error in qr sending SMS   " + str(ve)
@frappe.whitelist(allow_guest=False)
def send_sms_twilio(phone_number, otp):
    """Sends an SMS using Twilio API."""
    try:

        phone_number = "+91" + phone_number
        parts = get_sms_id("twilio").split(":")

        url = f"https://api.twilio.com/2010-04-01/Accounts/{parts[0]}/Messages.json"

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
            return True
        else:
            return response.text

    except ValueError as ve:
        return "Error in qr sending SMS   " + str(ve)


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
            json.dumps({"message": "Customer not found", "user_count": 0}),
            status=STATUS,
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
            json.dumps({"message": "Customer not found", "user_count": 0}),
            status=STATUS,
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
            f"&from=DEFAULT"
            f"&to={phone_number}"
            f"&text={message_text}"
            f"&type=unicode"
        )
        headers = {"Content-Type": APPLICATION_FORM_URLENCODED}

        response = requests.request(
            "POST", url, headers=headers, data=payload, timeout=10
        )

        if response.status_code in (STATUS_200, 201):
            return True
        else:
            return False
    except ValueError as ve:
        frappe.log_error(f"Error in sending SMS: {ve}")
        return False


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
    sco_pes = ["https://www.googleapis.com/auth/firebase.messaging"]
    credential = service_account.Credentials.from_service_account_file(
        "dallah-fcm.json", scopes=sco_pes
    )
    request = google.auth.transport.requests.Request()
    credential.refresh(request)
    return credential.token