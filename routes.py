from flask import render_template, request
from appli_flask import app
from .forms import DNSQueryForm
from .my_dns.dns_resolv import *
import logging
from datetime import datetime


@app.route("/", methods=["GET", "POST"])
def dns_query():
    form = DNSQueryForm()
    if form.validate_on_submit():
        query_type = form.query_type.data
        dns_server = form.dns_server.data or "1.1.1.1"
        fqdn = form.fqdn.data

        MESSAGE = set_query(fqdn, query_type)

        data = send_query(MESSAGE, dns_server)

        log_message = f"IP: {request.remote_addr} - Date/hour: {datetime.now()} - Query: {query_type}, {dns_server}, {fqdn}, Answer: {get_rrs(data)}"
        logging.info(log_message)

        return render_template("index.html", form=form, data=get_rrs(data))
        

    return render_template("index.html", form=form)
