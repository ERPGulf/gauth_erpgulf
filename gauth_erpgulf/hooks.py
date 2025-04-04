app_name = "gauth_erpgulf"
app_title = "gauth_erpgulf"
app_publisher = "ERPGulf"
app_description = "Authentication and API for Frappe ERPNext framework from ERPGulf"
app_email = "support@erpgulf.com"
app_license = "mit"

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "gauth_erpgulf",
# 		"logo": "/assets/gauth_erpgulf/logo.png",
# 		"title": "gauth_erpgulf",
# 		"route": "/gauth_erpgulf",
# 		"has_permission": "gauth_erpgulf.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/gauth_erpgulf/css/gauth_erpgulf.css"
# app_include_js = "/assets/gauth_erpgulf/js/web_log.js"

# include js, css files in header of web template
# web_include_css = "/assets/gauth_erpgulf/css/gauth_erpgulf.css"
# web_include_js = "/assets/gauth_erpgulf/js/gauth_erpgulf.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "gauth_erpgulf/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_list_js = {"doctype" : "gauth_erpgulf/public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}
doctype_js = {
    "Backend Server Settings": "public/js/web_log.js",
}
# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "gauth_erpgulf/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "gauth_erpgulf.utils.jinja_methods",
# 	"filters": "gauth_erpgulf.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "gauth_erpgulf.install.before_install"
# after_install = "gauth_erpgulf.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "gauth_erpgulf.uninstall.before_uninstall"
# after_uninstall = "gauth_erpgulf.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "gauth_erpgulf.utils.before_app_install"
# after_app_install = "gauth_erpgulf.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "gauth_erpgulf.utils.before_app_uninstall"
# after_app_uninstall = "gauth_erpgulf.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "gauth_erpgulf.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
# 	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

scheduler_events = {
    "cron": {
            "0 2 * * *": [
            "gauth_erpgulf.gauth_erpgulf.web_logging.enqueue_parse_nginx_logs"
        ],
        # "0 2 * * *": [
        #     "gauth_erpgulf.gauth_erpgulf.web_logging.delete_all_web_access_logs_async"
        # ],
    },
    # "all": [
    #     "gauth_erpgulf.tasks.all"
    # ],
    # "daily": [
    #     "gauth_erpgulf.tasks.daily"
    # ],
    # "hourly": [
    #     "gauth_erpgulf.tasks.hourly"
    # ],
    # "weekly": [
    #     "gauth_erpgulf.tasks.weekly"
    # ],
    # "monthly": [
    #     "gauth_erpgulf.tasks.monthly"
    # ],
}

# Testing
# -------

# before_tests = "gauth_erpgulf.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "gauth_erpgulf.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "gauth_erpgulf.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = [
#    "gauth_erpgulf.gauth_erpgulf.backend_server."
#    "check_country_restriction",
#    "gauth_erpgulf.gauth_erpgulf.web_logging.mark_primary_request",
# ]
# before_request = [
#     "gauth_erpgulf.gauth_erpgulf.web_logging.mark_primary_request",
# ]
after_request = [
    "gauth_erpgulf.gauth_erpgulf.web_logging.enable_api_call",
]


# Job Events
# ----------
# before_job = ["gauth_erpgulf.utils.before_job"]
# after_job = ["gauth_erpgulf.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"gauth_erpgulf.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }

# fixtures = [
#     {"dt": "DocType", "filters": {"module": "gauth_erpgulf"}},
# ]
fixtures = [
    {

        "dt": "Countries and IP address",
        "filters": [
            ["parent", "=", "Backend Server Settings"]
        ]
    }
]



