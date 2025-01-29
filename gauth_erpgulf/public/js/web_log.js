function getStandardConfirmationMessage() {
    return __('This process will take a long time depending on the log size and will continue running in the background even if you close this window.The updates will be available in the Error Log.Do you want to continue?'
);
}
frappe.ui.form.on("Backend Server Settings", {
    refresh: function (frm) {
        // Add any refresh logic here
        // Call the update_now event
    },
    update_now: function (frm) {
        console.log("web_log.js loaded");
        
        // Add confirmation logic
        frappe.confirm(
            getStandardConfirmationMessage(),
            function () { 
                // Logic for when the user confirms
                // frappe.msgprint('Update process started!');
                // Call the backend method
                frappe.call({
                    method: 'gauth_erpgulf.gauth_erpgulf.web_logging.enqueue_parse_nginx_logs',
                    freeze: true,
                    freeze_message: __('<span style="display: block; text-align: center;">'
                        + '<img src="https://global.discourse-cdn.com/sitepoint/original/3X/e/3/e352b26bbfa8b233050087d6cb32667da3ff809c.gif" alt="Processing" style="width: 100px; height: 100px;"></br>'
                        + 'Please Wait...</br>Connecting to the remote server to retrieve data</span>'),
                    callback: function (r) {
                        if (r.message) {
                            frappe.msgprint('The process has been started successfully.');
                            frm.set_value("last_updated_date", frappe.datetime.now_datetime());
                        }
                    },
                    error: function (err) {
                        frappe.msgprint('An error occurred. Check error logs for details.');
                    }
                });
            },
            function () {
                // Logic for when the user cancels
                frappe.msgprint('Process cancelled.');
            }
        );
    },
    test_send_email: function (frm) {
        frappe.confirm("Do you want to send the test Email?", function () {
            frappe.call({
                method: "frappe.client.get",
                args: {
                    doctype: "Email Template",
                    name: "gauth erpgulf" // Replace with your template name
                },
                callback: function (template_response) {
                    if (template_response.message) {
                        console.log("Template loaded")
                        const template = template_response.message;
                        let body_html = template.response_html;
    
                        // Replace placeholder in the template
                        body_html = body_html.replace("John Deo", "User");
    
                        frappe.call({
                            method: 'gauth_erpgulf.gauth_erpgulf.backend_server.send_email_oci',
                            args: {
                                "recipient": frm.doc.email_address, // Corrected reference to recipient
                                "subject": template.subject,
                                "body_html": body_html
                            },
                            freeze: true,
                            freeze_message: __('<span style="display: block; text-align: center;">'
                                + '<img src="https://global.discourse-cdn.com/sitepoint/original/3X/e/3/e352b26bbfa8b233050087d6cb32667da3ff809c.gif" alt="Processing" style="width: 100px; height: 100px;"></br>'
                                + 'Please Wait...</br>Connecting to the remote server to retrieve data</span>'),
                            callback: function (email_response) {
                                if (email_response.message) {
                                    frappe.msgprint("The Email has been sent successfully.");
                                } else {
                                    frappe.msgprint("There was an error sending the email. Please check the logs.");
                                    frappe.call({
                                        method: "frappe.utils.error_log.log_error",
                                        args: {
                                            title: "Email Sending Error",
                                            message: "There was an error while sending the email to " + frm.doc.recipient
                                        }
                                    });
                                }
                            },
                            error: function (err) {
                                frappe.msgprint("An error occurred while sending the email.");
                            }
                        });
                    } else {
                        frappe.msgprint("Email Template could not be found.");
                    }
                },
                error: function (err) {
                    frappe.msgprint("Failed to fetch email template. Check error logs for details.");
                }
            });
        },
            function () {
                frappe.msgprint("Email sending cancelled.");
            });
    }    
});
