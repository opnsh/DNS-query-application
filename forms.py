from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError
import re

class DNSQueryForm(FlaskForm):
    query_type = SelectField('Type of DNS request', choices=[
        ('A', 'Type A'),
        ('NS', 'Type NS'),
        ('CNAME', 'Type CNAME'),
        ('SOA', 'Type SOA'),
        ('PTR', 'Type PTR'),
        ('MX', 'Type MX'),
        ('AAAA', 'Type AAAA')
    ], validators=[DataRequired()])
    dns_server = StringField('DNS server to query (Default 1.1.1.1)')
    fqdn = StringField('FQDN to query', validators=[DataRequired()])
    submit = SubmitField('Send')

    def validate_dns_server(form, field):
        ip_regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        ip_regex2 = r"^$"
        if re.match(ip_regex2, field.data):
            pass
        else :
            if not re.match(ip_regex, field.data):
                raise ValidationError("⚠ Invalid DNS IP address ⚠")
