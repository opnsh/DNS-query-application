from flask import Flask
import logging

app = Flask(__name__)
app.secret_key = 'Fields to be replaced by your key'

logging.basicConfig(filename='log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

from appli_flask import routes
from appli_flask import error_handlers

"""This python package is realized in the framework of the SAé15, Processing Data, project of the BUT1 - Networks and Telecommunications. Its objective is to provide tools to query a DNS server :

* Form the DNS packets of the requests according to the recommendations of the RFC 1035 ; 
* Process the data received in the DNS response frame.

The RFC1035 describes the details of the domain system and protocol.

All communications inside of the domain protocol are carried in a single
format called a message.  The top level format of message is divided
into 5 sections (some of which are empty in certain cases).

Message format
===============

+------------+--------------------------------------------------------+
| Header     | fields that specify which of the remaining sections    |
| 12 bytes   | are present and the message properties                 |
+------------+--------------------------------------------------------+
| Question   | the question for the name server                       |
+------------+--------------------------------------------------------+
| Answer     | RRs answering the question                             |
+------------+--------------------------------------------------------+
| Authority  | RRs pointing toward an authority name server           |
+------------+--------------------------------------------------------+
| Additional | RRs holding additional information which relate to the |
|            | query, but are not strictly answers for the question   |
+------------+--------------------------------------------------------+

"""

#:Dictionary that lists the type codes of DNS queries and their respective values in byte array
TYPE = {'A':b'\x00\x01', 
        'NS':b'\x00\x02', 
        'CNAME':b'\x00\x05',
        'SOA':b'\x00\x06',
        'WKS':b'\x00\x0b',
        'PTR':b'\x00\x0c',
        'MX':b'\x00\x0f',
        'SRV':b'\x00\x21',
        'AAAA':b'\x00\x1c'
        }


#:Dictionary that lists the class codes of DNS queries and their respective values in byte array
CLASS = {'IN':b'\x00\x01',  # 
        'CS':b'\x00\x02',   # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        'CH':b'\x00\x05',   # the CHAOS class
        'HS':b'\x00\x06'    # Hesiod [Dyer 87]        
        }

idcount = 0
