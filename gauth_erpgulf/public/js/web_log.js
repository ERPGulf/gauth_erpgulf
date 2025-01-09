function getStandardConfirmationMessage() {
    return __('This process will take a long time depending on the log size and will continue running in the background even if you close this window.The updates will be available in the Error Log.<br>Do you want to continue?'
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
    }
});
