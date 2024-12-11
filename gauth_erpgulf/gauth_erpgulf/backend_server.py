"""
This module generates a secure token for the application.

Args:
    api_key (str): The API key provided by the client.
    api_secret (str): The API secret provided by the client.
    app_key (str): The application key to decode.

Returns:
    Response: A JSON response indicating success or failure.
"""

import base64
import json
import requests
import frappe
from werkzeug.wrappers import Response


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

        except ValueError as e:
            return Response(
                json.dumps(
                    {
                        "message": "Mismatch in expected database results",
                        "error": str(e),
                    }
                ),
                status=500,
                mimetype="application/json",
            )
        except ConnectionError as e:
            return Response(
                json.dumps({"message": "Database connection failed", "error": str(e)}),
                status=500,
                mimetype="application/json",
            )
        except TimeoutError as e:
            return Response(
                json.dumps({"message": "Database query timed out", "error": str(e)}),
                status=500,
                mimetype="application/json",
            )
        except (AttributeError,Exception as e:
            return Response(
                json.dumps(
                    {
                        "message": "Invalid database object or method call",
                        "error": str(e),
                    }
                ),
                status=500,
                mimetype="application/json",
            )
        except (
            BaseException
        ) as e:
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
            # "grant_type": "refresh_token"
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
                result_data = json.loads(response.text)
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
        # frappe.local.response.http_status_code = 401
        # return json.loads(response.text)
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )


@frappe.whitelist(allow_guest=False)
def generate_token_secure_for_users(username, password, app_key):
    """
    Generates a secure token for users using the provided API credentials.

    This function authenticates a user by validating the provided API key,
    API secret, and application key. It retrieves client credentials from
    the database and interacts with the OAuth service to generate a secure token.

    Args:
        username (str): The username of the user requesting authentication.
        password (str): The password associated with the user.
        app_key (str): A base64-encoded application key.

    Returns:
        Response: A JSON response containing the token if successful, or an
                  error message and status code if the authentication fails.
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
            # "grant_type": "refresh_token"
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
            # frappe.get_doc(
            #     {
            #         "doctype": "log_in details",
            #         "user": username,
            #         "time": now,
            #     }
            # ).insert(ignore_permissions=True)
            response_data = json.loads(response.text)

            result = {
                "token": response_data,
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
        # frappe.local.response.http_status_code = 401
        # return json.loads(response.text)
        return Response(
            json.dumps({"message": e, "user_count": 0}),
            status=500,
            mimetype="application/json",
        )