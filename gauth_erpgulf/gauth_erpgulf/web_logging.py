import frappe
import re
from datetime import datetime, timezone
WEB_ACCESS_LOG = "Web Access Log"


@frappe.whitelist(allow_guest=True)
def delete_all_web_access_logs_async():
    """
    Enqueue a background job to clear 'Web Access Log' records.

    Returns:
        str: A message indicating the deletion process has started.
    """
    # Enqueue the deletion process as a background job
    frappe.enqueue(
        "gauth_erpgulf.gauth_erpgulf.web_logging.delete_all_web_access_logs",
        timeout=14400,
    )
    return "Deletion of Web Access Log records has been started."


def delete_all_web_access_logs():
    """
    Actual function to delete all records from the 'Web Access Log' doctype.
    This function is intended to be run in the background.
    """


    doctype_name = WEB_ACCESS_LOG
    records = frappe.get_all(doctype_name, pluck="name")
    if not records:
        frappe.log_error(
                            "No records found in Web Access Log.",
                            "Delete Web Access Log"
                        )
        return

    records_deleted = 0

    for record_name in records:
        frappe.delete_doc(doctype_name, record_name, ignore_permissions=True)
        records_deleted += 1

        # Commit periodically to avoid long transaction locks
        if records_deleted % 100 == 0:
            frappe.db.commit()

    # Final commit
    frappe.db.commit()
    frappe.log_error(
        f"Successfully deleted {records_deleted} records from Web Access Log.",
        "Delete Web Access Log",
    )


@frappe.whitelist(allow_guest=True)
def enqueue_parse_nginx_logs():
    """
    Enqueue the parse_nginx_logs function to run in the background.
    """

    result = frappe.get_value(
        "Backend Server Settings", None, "activate_scheduled_update"
    )
    if int(result) != 0:
        frappe.log_error("Log Parsing Activated", "Log Parsing")
        frappe.enqueue(
            "gauth_erpgulf.gauth_erpgulf.web_logging.parse_nginx_logs",
            timeout=14400
        )
    return "Nginx log parsing has been started as a background job."


def parse_nginx_logs():
    """
    Parse Nginx logs and insert records into the 'Web Access Log' doctype.
    Only records newer than the latest existing entry in the doctype are added.
    """


    frappe.log_error("Result fetched: parsing", "Nginx Log")
    log_file_path = "/var/log/nginx/access.log"
    # Regular expression to parse Nginx logs
    log_pattern = re.compile(
        r"(?P<remote_addr>[^ ]*) [^ ]* [^ ]* \[(?P<time_local>[^\]]*)\] "
        r'"(?P<request>[^"]*)" (?P<status>[0-9]*) (?P<body_bytes_sent>[0-9]*) '
        r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
    )
    # Fetch the latest log datetime from the 'Web Access Log' doctype
    latest_log = frappe.db.get_value(
        WEB_ACCESS_LOG,
        filters={},
        fieldname=["date", "time"],
        order_by="date DESC, time DESC",
    )
    frappe.log_error("Latest Log fetching", "Fetching")

    if latest_log:
        # Combine date and time into a single datetime object
        latest_datetime_str = f"{latest_log[0]} {latest_log[1]}"
        latest_datetime = datetime.strptime(
                                                latest_datetime_str,
                                                "%Y-%m-%d %H:%M:%S"
                                            )
        latest_datetime = latest_datetime.replace(tzinfo=timezone.utc)
    else:
        # If no records exist, parse all logs
        latest_datetime = None

    records_added = 0
    frappe.log_error("Opening Log file path", "Opening path")
    # Open and parse the Nginx log file
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = log_pattern.match(line)
            if match:
                log_datetime = datetime.strptime(
                    match.group("time_local"), "%d/%b/%Y:%H:%M:%S %z"
                )

                # Process only newer records
                if not latest_datetime or log_datetime > latest_datetime:
                    request_parts = match.group("request").split()
                    api_type = (
                        request_parts[0]
                        if len(request_parts) > 0
                        else "UNKNOWN"
                    )

                    # Create a new record in the 'Web Access Log' doctype
                    doc = frappe.get_doc(
                        {
                            "doctype": WEB_ACCESS_LOG,
                            "remote_address": match.group("remote_addr"),
                            "date": log_datetime.strftime("%Y-%m-%d"),
                            "time": log_datetime.strftime("%H:%M:%S"),
                            "api_type": api_type,
                            "request": match.group("request"),
                            "status": match.group("status"),
                            "bytes_sent": match.group("body_bytes_sent"),
                            "referer": match.group("http_referer"),
                            "user_agent": match.group("http_user_agent"),
                        }
                    )

                    # Insert the record into the database
                    doc.insert(ignore_permissions=True)
                    records_added += 1

    frappe.db.commit()  # Commit all changes to the database
    frappe.db.set_value(
        "Backend Server Settings",
        None,  # This assumes there is only one Backend Server Settings record
        "last_updated_date",
        frappe.utils.now_datetime(),  # Set the current timestamp
    )
    frappe.log_error(
        f"Successfully added {records_added} new log records.",
        "Nginx Log Parsing"
    )
    return f"Successfully added {records_added} new log records."
