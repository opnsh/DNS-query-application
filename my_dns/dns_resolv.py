from typing import Dict
from appli_flask.__init__ import TYPE, CLASS, idcount


def send_query(query, dns_server):
    """Send a dns packet datagram on the network and return the response receive packet.

    This function uses a **network socket** to send a **dns_packetgram message** to a DNS server. The message carried by the dns_packetgram is a DNS query. The transport protocol used is UDP. It returns the DNS response and then closes the socket at the end of the execution.

    :param query: the packet of bytes that constitutes a complete request
    :param dns_server: IP address or FQDN of the server
    :type query: array of bytes
    :type dns_server: string

    :return: array of bytes representing the response

    """

    import socket

    UDP_PORT = 53

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(query, (dns_server, UDP_PORT))
        sock.settimeout(10)
        dns_packet, addr = sock.recvfrom(1024) # buffer size is 1024 bytes

    except:
        print("No response from serveur !")
        dns_packet=None

    finally:
        print("Connection closed !")
        sock.close()
    return dns_packet

def set_query(query_name, query_type):
    """Uses the query and type parameters to form the byte packet representing the DNS query to be sent.

    * The first twelve bytes are the header of th DNS request
    * Next bytes represents the question.

    .. Important::
        extract from the **RFC1035** (*3.1. Name space definition*)

        *Domain names in messages are expressed in terms of a sequence of labels. Each label is represented as a one byte length field followed by that number of bytes. Since every domain name ends with the null label of the root, a domain name is terminated by a length byte of zero. The high order two bits of every length byte must be zero, and the remaining six bits of the length field limit the label to 63 bytes or less.*


    :param query_name: FQDN or Domain Nale or IP Address to resolve
    :param query_type: Type of DNS resolution
    :type query_name: string
    :type query_type: string

    :return: array of bytes représenting de query.
    """

    global idcount
    idcount += 1

    ID = idcount.to_bytes(2, 'big') # convert to 2 bytes in bigEndian représentation 
                                    # (the most significant byte is at the beginning of the byte array)
    FLAGS = b'\x01\x00'
    QDCOUNT = b'\x00\x01'
    ANCOUNT = b'\x00\x00'
    NSCOUNT = b'\x00\x00'
    ARCOUNT = b'\x00\x00'
    header = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    # Another method is to create the byte array directly
    # header = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    query = None

    labels = query_name.split('.')

    if query_type == 'PTR':
        for label in labels:
            try:
                int(label)
            except:
                print("ERROR : Illegal use of PTR request")
                print("You need to enter an IPV4 address")

        labels = labels[::-1]
        labels.append("in-addr")
        labels.append("arpa")

    for label in labels:
        if query == None:
            query = bytes([len(bytes(label,'utf-8'))]) + bytes(label, 'utf-8')
        else:
            query += bytes([len(bytes(label,'utf-8'))]) + bytes(label, 'utf-8')
    
    query += b'\x00'

    # Concatenation of header with the QNAME, QTYPE and QCLASS fields according 
    # RFC1035 specifications
    return header + query + TYPE.get(query_type) + CLASS.get('IN')


def get_header(dsn_packet):
    """Extract the ID, the FLAG, the QDCOUNT, ANCOUNT, NSCOUNT and the ARCOUNT from the **dns_packet** argument and return a dictionnary representing every parts

    .. Important::

        in the flag, there are QR, OPCODE, AA, TC, RD, RA, Z and RCODE, I put the id and the FLAG are contained in a single category, the HEAD.:

        +---------------------+------------------------------------+
        |        Head         |          4 bytes                   |
        +---------------------+------------------------------------+
        |       QDCOUNT       |          2 bytes                   |
        +---------------------+------------------------------------+
        |       ANCOUNT       |          2 bytes                   |
        +---------------------+------------------------------------+
        |       NSCOUNT       |          2 bytes                   |
        +---------------------+------------------------------------+
        |       ARCOUNT       |          2 bytes                   |
        +---------------------+------------------------------------+

        The header is the grouping of all the parts seen above, it is 12 bytes.

    :return: dictionary of query fields.

    """ 
    #set the first 12 bytes as header bytes
    head=dsn_packet[0:12]
    #capture the flag 
    flag = int.from_bytes(head[2:4],'big')
    #cutting of the head 
    head = {'id' : int.from_bytes(head[0:2],'big'),
            'flag' : {"QR" : (flag >> 15), 'Opcode' : (flag >> 11 & 0x0f), 'AA' :(flag >> 10 &0x01), 'TC' : (flag >> 9 & 0x01), 'RD' : (flag >> 8 & 0x01), 'RA' : (flag >> 7 & 0x01), 'Z' : (flag >> 4 & 0x07), 'Rcode' : (flag & 0x0f) },
            'QDCOUNT' : int.from_bytes(head[5:6],'big'), 'ANCOUNT' : int.from_bytes(head[7:8],'big'), 'NSCOUNT' : int.from_bytes(head[9:10],'big'), 'ARCOUNT' : int.from_bytes(head[11:12],'big')}
    return head


def get_query(dns_packet):
    """Extract the DNS QUERY from the **dns_packet** argument and return a dictionnary representing the different fields of the QUERY

    .. Important::
        extract from the **RFC1035** : *4.1 Format*

        All communications inside of the domain protocol are carried in a single
        format called a message.  The top level format of message is divided
        into 5 sections (some of which are empty in certain cases) shown below:

        +---------------------+------------------------------------+
        |        Header       |                                    |
        +---------------------+------------------------------------+
        |       Question      | the question for the name server   |
        +---------------------+------------------------------------+
        |        Answer       | RRs answering the question         |
        +---------------------+------------------------------------+
        |      Authority      | RRs pointing toward an authority   |
        +---------------------+------------------------------------+
        |      Additional     | RRs holding additional information |
        +---------------------+------------------------------------+

        The header section is always present.  The header includes fields that
        specify which of the remaining sections are present, and also specify
        whether the message is a query or a response, a standard query or some
        other opcode, etc.

        The names of the sections after the header are derived from their use in
        standard queries.  The question section contains fields that describe a
        question to a name server.  These fields are a query type (QTYPE), a
        query class (QCLASS), and a query domain name (QNAME).

        The last three sections have the same format: a possibly empty list of
        concatenated resource records (RRs).  The answer section contains RRs
        that answer the question; the authority section contains RRs that point
        toward an authoritative name server; the additional records section
        contains RRs which relate to the query, but are not strictly answers
        for the question.

    :param dns_packet: The  packet received to analysis
    :type dns_packet: array of bytes

    :return: dictionary of query fields.
    :rtype: Dict

    """

    idx_end = dns_packet.find(b'\x00',12) # '... domain name is terminated by a length byte of zero ...
    query = dns_packet[12:idx_end]          # Isolate the bytes representing the question
     
    # Query traitment - extract Fully Qualified Domain Name recovery
    idx_start = 0                           # idx_start represent a length Label byte
    idx_end = int(query[idx_start]+1)      
    dns_query = query[idx_start+1:idx_end]  # extract bytes representing first label

    while idx_end < len(query):             # Loop to extract the other labels and build th FQDN
        idx_start = idx_end
        idx_end = idx_start + int(query[idx_start]+1)
        dns_query += b'.'+ query[idx_start+1:idx_end]
    # Query traitment - extract DNS query Type 
    query_type = dns_packet[idx_end + 12 + 1: idx_end + 12 + 3]      # extract bytes representing QTYPE field
    QTYPE = list(TYPE.keys())[list(TYPE.values()).index(query_type)] # get the DNS Type 

    # Query traitment - extract DNS query class 
    query_class = dns_packet[idx_end + 12 + 3: idx_end + 12 + 5]      # extract bytes representing QCLASS field
    QCLASS = list(CLASS.keys())[list(CLASS.values()).index(query_class)] # get the DNS Class

    return {'QNAME': dns_query.decode(), 'TYPE': QTYPE, 'CLASS':QCLASS, 'QLENGTH': idx_end + 5}

def get_rr_suffix(idx, dns_packet):
    """Extract the **domain name** or the **suffix** of a resource record from the ``dns_packet`` argument. It return a string representing the name of the current record or its *rdata*.

    .. Important::

        Extract from the **RFC1035** (*3.1. Name space definitions*)

        * Domain names in messages are expressed in terms of a sequence of labels. Each label is represented as a one byte length field followed by that number of bytes. Since every domain name ends with the null label of the root, a domain name is terminated by a length byte of zero. The high order two bits of every length byte must be zero, and the remaining six bits of the length field limit the label to 63 bytes or less.*::

            +--+--+--+--+--+--+--+--+
            | 0 0 |  LABEL LENGTH   |
            +--+--+--+--+--+--+--+--+

        * In order to reduce the size of messages, the domain system utilizes a compression scheme which eliminates the repetition of domain names in a message.  In this scheme, an entire domain name or a list of labels at the end of a domain name is replaced with a pointer to a prior occurance of the same name.

        The pointer takes the form of a two bytes sequence::

            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            | 1  1|                OFFSET                   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        The first two bits are ones.  This allows a pointer to be distinguished from a label, since the label must begin with two zero bits because labels are restricted to 63 bytes or less.  (The 10 and 01 combinations are reserved for future use.)  The OFFSET field specifies an offset from the start of the message (i.e., the first byte of the ID field in the domain header).  A zero offset specifies the first byte of the ID field, etc.

        The compression scheme allows a domain name in a message to be represented as either:

        * a sequence of labels ending in a zero byte
        * a pointer
        * a sequence of labels ending with a pointer

    :param dns_packet: The  packet received to parse
    :param idx: The position in packet byte array where the parsing should start
    :type packet: array of bytes
    :type idx: Integer
    :return: The domain name of the record.
    :rtype: String

    """

    rr_suffix = b''
    if dns_packet[idx] >= 0xc0:
        idx = int.from_bytes(dns_packet[idx:idx+2], 'big') & 0x3fff

    while 0 < int(dns_packet[idx]) < 0x40:
        if rr_suffix == b'':
            rr_suffix = dns_packet[idx+1:idx+int(dns_packet[idx]+1)]
        else:
            rr_suffix += b'.' + dns_packet[idx+1:idx+int(dns_packet[idx]+1)]
        idx += int(dns_packet[idx]) + 1

        # test if next bytes are labels or pointer 
        if dns_packet[idx] >= 0xc0:
            idx = int.from_bytes(dns_packet[idx:idx+2], 'big') & 0x3fff
    
    return rr_suffix.decode('utf-8')

def get_fields(dns_records):
    """Extract the TYPE, CLASS, TTL and the RDLENGHT from the **dns_records** argument and return a dictionnary representing the different fields

    .. Important::

        The four parts of the field are 10 bytes long in total:


        +---------------------+------------------------------------+
        |      TYPE           |            2 bytes                 |
        +---------------------+------------------------------------+
        |      CLASS          |            2 bytes                 |
        +---------------------+------------------------------------+
        |      TTL            |            4 bytes                 |
        +---------------------+------------------------------------+
        |      RDLENGHT       |            2 bytes                 |
        +---------------------+------------------------------------+
        

    :return: dictionary of fields.

    """
    # Get the type (2 bytes)
    q_type = list(TYPE.keys())[list(TYPE.values()).index(dns_records[:2])]
    # Get the class (2 bytes)
    q_class = list(CLASS.keys())[list(CLASS.values()).index(dns_records[2:4])]
    # Get the ttl (4 bytes)
    q_ttl = int.from_bytes(dns_records[4:8], byteorder='big')
    # Get the rdlength (2 bytes)
    q_rdlength = int.from_bytes(dns_records[8:10], byteorder='big')

    return {"rr_type" : q_type, "rr_class" : q_class, "rr_ttl" : q_ttl, "rr_length" : q_rdlength }

def get_rrs(dns_packet):
    """Extract the **Ressource Records** (*RRs*) from the ``dns_packet`` argument and return a dictionnary representing the different records. Each RR is a dictionary of DNS fields.

    .. Important::

        The answer, authority, and additional sections all share the same
        format: a variable number of resource records, where the number of
        records is specified in the corresponding count field in the header.
        Each resource record has the following format::

            0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      NAME                     |   Tomain name of this resource record
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TYPE                     |   2 bytes of the RR type codes
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     CLASS                     |   2 bytes of the RR class codes
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TTL                      |   32 bit unsigned integer, time interval (in seconds) that the resource record may be cached before it should be discarded
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                   RDLENGTH                    |   16 bit unsigned integer that specifies the length in bytes of the RDATA field
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
            |                     RDATA                     |   Variable length byte array that describe the resource,
            |                                               |   The format varies according to the TYPE and CLASS of the resource record
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    :param dns_packet: The  packet received to analysis
    :type dns_packet: array of bytes
    :return: dictionary of query fields.
    :rtype: Dict

    """

    # Initiate the dictionary of RRs to return
    rrs = {"answers":{}, "authorities":{}, "additionals":{}}

    # Initialization local variables
    idx_next=0
    idx_start_name = 0
    idx_current = 0
    cursor = 0

    # Extract the header to get the number of ressource records in each section of the response : answer, authority and additional
    header = get_header(dns_packet)
    nb_records = header.get('ANCOUNT') + header.get('NSCOUNT') + header.get('ARCOUNT')

    # Extract the query to get the size of the query and deduct the start index of the RRS in the response byte array
    query = get_query(dns_packet)

    # Extract form the response a byte array of all the RRs 
    dns_records = dns_packet[query.get('QLENGTH') + 12:]        # Byte array of all the RRs from DSN response

    # Extract all fieads of each RRs of the response
    while nb_records > 0:
        rr_name = ''
        dict_record = {}
        idx_start_name = idx_current
   
        # Test if rr_name is a pointer to another position in the array (first byte value upper than '0xc0') or a length label
        if int(dns_records[idx_start_name]) >= 0xc0:
            # Get the pointer value from the 14 low order bits of the 2 bytes representing the position index of next label bytes
            cursor = int.from_bytes(dns_records[idx_start_name:idx_start_name+2], 'big') & 0x3fff 
            idx_current = idx_start_name + 2
            
        else:
            while 0 < int(dns_records[idx_start_name]) < 0x40:
                if rr_name == '':
                    rr_name = dns_records[idx_start_name+1:idx_start_name+int(dns_records[idx_next + idx_start_name]+1)].decode()
                else:
                    rr_name += '.' + dns_records[idx_start_name+1:idx_start_name+int(dns_records[idx_next + idx_start_name]+1)].decode()

                idx_start_name += int(dns_records[idx_start_name]) + 1

                # test if next byte is a pointer to another position in the array
                if dns_records[idx_start_name] >= 0xc0:
                    idx_current = idx_start_name + 2
                    cursor = int.from_bytes(dns_records[idx_start_name:idx_start_name+2], 'big') & 0x3fff
                    break
        if cursor != 0 :
            rr_name += get_rr_suffix(cursor, dns_packet)            
        else :
            idx_current = idx_start_name + 1

        dict_record["rr_name"] = rr_name

        # Query traitment - extract DNS Answer Resource Record  Type nb_RRs
        fields = get_fields(dns_records[idx_current:])
        idx_current += 10

        dict_record = {**dict_record, **fields}

        if fields.get("rr_type") == 'A':
            rdata = get_rdata_A(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'NS':
            rdata = get_rdata_NS(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'CNAME':
            rdata = get_rdata_CNAME(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'SOA':
            rdata = get_rdata_SOA(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'PTR':
            rdata = get_rdata_PTR(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'MX':
            rdata = get_rdata_MX(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'AAAA':
            rdata = get_rdata_AAAA(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        if nb_records > header.get('NSCOUNT') + header.get('ARCOUNT'):
            if rrs.get("answers").get(rr_name) == None:
                rrs.get("answers")[rr_name]=[]
            rrs.get("answers")[rr_name].append(dict_record)
        elif nb_records > header.get('ARCOUNT'):
            if rrs.get("authorities").get(rr_name) == None:
                rrs.get("authorities")[rr_name]=[]
            rrs.get("authorities")[rr_name].append(dict_record)
        elif nb_records > 0:
            if rrs.get("additionals").get(rr_name) == None:
                rrs.get("additionals")[rr_name]=[]
            rrs.get("additionals")[rr_name].append(dict_record)

        idx_start_name = idx_current + 10
        idx_next = idx_start_name
        nb_records -= 1
    return rrs

def get_rdata_name(cursor, dns_packet): 
    """    
    Extract the domain name of the Ressource Record from the RR’s rdata field and return it in string format. it calls the get_rdata_suffix(cursor, dns_packet) to do this.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: the domain name in DNS rdata ressource record.
    :rtype: string

    """
    name = get_rr_suffix(cursor, dns_packet)
    return {'rdata_name' : (name)}

def get_rdata_A(cursor, dns_packet):
    """    
    Extract the IPV4 Network Address of the Ressource Record from the RR’s rdata field and return it.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: A Dictionary with a single key ‘IPV4 address’ whose value is the IPV4 Network Address string of rdata ressource record
    :rtype: Dict

    """ 
    #setting of all cursor positions
    first_cursor = cursor+1
    second_cursor = cursor+2
    third_cursor = cursor+3
    last_cursor = cursor+4
    # capture the first part of the ip address
    rdata_part_1 = int.from_bytes(dns_packet[cursor: first_cursor], byteorder='big')
    # capture the second part of the ip address
    rdata_part_2 = int.from_bytes(dns_packet[first_cursor: second_cursor], byteorder='big')
    # capture the third part of the ip address
    rdata_part_3 = int.from_bytes(dns_packet[second_cursor: third_cursor], byteorder='big')
    # capture the last part of the ip address
    rdata_part_4 = int.from_bytes(dns_packet[third_cursor: last_cursor], byteorder='big')
    p = rdata_part_1 ,rdata_part_2, rdata_part_3, rdata_part_4
    s = str(p)
    ip = s.replace(',', '.')
    return {'Adresse ip' : ip }

def get_rdata_NS(cursor, dns_packet):
    """    
    Extract the domain name of the Ressource Record from the RR’s rdata field in NS response and return it.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: A Dictionary with a single key ‘Name server’ whose value is the domain name string of rdata ressource record.
    :rtype: Dict

    """ 
    NS = get_rdata_name(cursor, dns_packet)
    return {'rdata_NS' :(NS)}

def get_rdata_CNAME(cursor, dns_packet):
    """    
    Extract the domain name of the Ressource Record from the RR’s rdata field in CNAME response and return it.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: A Dictionary with a single key ‘Canonical name’ whose value is the domain name string of rdata ressource record
    :rtype: Dict

    """ 
    CNAME = get_rdata_name(cursor, dns_packet)
    return {'rdata_Cannonical Name' :(CNAME)}

def get_rdata_PTR(cursor, dns_packet):
    """    
    Extract the domain name of the Ressource Record from the RR’s rdata field in PTR response and return it.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: A Dictionary with a single key ‘Name’ whose value is the domain name string of rdata ressource record
    :rtype: Dict

    """ 
    PTR = get_rdata_name(cursor, dns_packet)
    return {'rdata_PTR' : (PTR)}

def get_rdata_MX(cursor, dns_packet):
    """    
    Extract the domain name and the priotrity of the Ressource Record from the RR’s rdata field of MX response and return it.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: A Dictionary with a two keys, ‘Mail exchanger’ whose value is the domain name string of rdata ressource record and ‘Preference’ whose value is an integer for the preference given to this RR at the same owner
    :rtype: Dict

    """
    fav = dns_packet[cursor:cursor+2]
    cursor+=2
    ex = get_rdata_name(cursor, dns_packet)
    return {'Pref' : (fav), 'Ex' : (ex)}

def get_rdata_SOA(cursor, dns_packet):
    """Extract the SOA fields of the **Ressource Record** from the rr's rdata field and return a dictionary. A SOA marks the start of a zone of authority.


    .. Important::

        SOA records cause no additional section processing. The fields below describe the Name Server.::

            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            /                     MNAME                     /   Name server that was the original original or
            /                                               /   primary source of data for this zone
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            /                     RNAME                     /   The mailbox of the person responsible for this zone
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    SERIAL                     |   The unsigned 32 bit version number of the
            |                                               |   original copy of the zone.
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    REFRESH                    |   A 32 bit time interval before the zone
            |                                               |   should be refreshed
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     RETRY                     |   A 32 bit time interval that should elapse
            |                                               |   before a failed refresh should be retried.
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    EXPIRE                     |   A 32 bit time value for the upper limit on the time  .
            |                                               |   interval before the zone is no longer authoritative
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    MINIMUM                    |   The unsigned 32 bit minimum TTL field that should be
            |                                               |   exported with any RR from this zone.
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    :param dns_packet: The  packet received to parse
    :param cursor: The  position in packet byte array where the parsing should start
    :type dns_packet: Array of bytes
    :type cursor: Integer
    :return: A Dictionary of SOA fields representing the name server in rdata ressource record.
    :rtype: Dict

    """

    idx = 0
    rdata_bytes = dns_packet[cursor:]   
    # Query traitment - extract Responsive authority's server name
    rdata_server = ''
    # Loop to get the first labels of server name
    while 0 < int(rdata_bytes[idx]) < 0x40:
        if rdata_server == '':
            rdata_server = rdata_bytes[idx + 1:int(rdata_bytes[idx]+1)].decode()
        else:
            rdata_server += '.' + rdata_bytes[idx + 1:int(rdata_bytes[idx]+1)].decode()
        
        idx += int(rdata_bytes[idx] + 1)
    
        # test if next byte is a pointer to another position in the array 
        if rdata_bytes[idx] >= 0xc0:
            cursor = int.from_bytes(rdata_bytes[idx:idx+2], 'big') & 0x3fff
            idx += 2
            break
    # Get the suffix of server name
    rdata_server += '.' + get_rr_suffix(cursor, dns_packet) 

    # Query traitment - extract Responsive authority's mail name
    rdata_mail = ''
    # Loop to get the first labels of server name
    while 0 < int(rdata_bytes[idx]) < 0x40:
        if rdata_mail == '':
            rdata_mail = rdata_bytes[idx + 1: idx + int(rdata_bytes[idx]) + 1].decode()
        else:
            rdata_mail += '.' + rdata_bytes[idx + 1 : idx + int(rdata_bytes[idx]) + 1].decode()

        idx += int(rdata_bytes[idx] + 1)

        # test if next byte is a pointer to another position in the array
        if rdata_bytes[idx] >= 0xc0:
            cursor = int.from_bytes(rdata_bytes[idx:idx+2], 'big') & 0x3fff
            idx += 2
            break
    # Get the suffix of mail name
    rdata_mail += '.' + get_rr_suffix(cursor, dns_packet)

    # Query traitment - extract Serial number
    rr_serial_bytes = rdata_bytes[idx: idx + 4]  
    rr_serial = int.from_bytes(rr_serial_bytes, 'big')

    # Query traitment - extract Refresh interval
    rr_refresh_bytes = rdata_bytes[idx + 4: idx + 8]
    rr_refresh = int.from_bytes(rr_refresh_bytes, 'big')

    # Query traitment - extract Retry interval
    rr_retry_bytes = rdata_bytes[idx + 8: idx + 12] 
    rr_retry = int.from_bytes(rr_retry_bytes, 'big')

    # Query traitment - extract Expire limit 
    rr_expire_bytes = rdata_bytes[idx + 12: idx + 16] 
    rr_expire = int.from_bytes(rr_expire_bytes, 'big')

    # Query traitment - extract Minimum TTL 
    rr_minttl_bytes = rdata_bytes[idx + 16: idx + 20]
    rr_minttl = int.from_bytes(rr_minttl_bytes, 'big')

    return {"Primary name server": rdata_server,
            "Responsive authority's mailbox": rdata_mail,
            "Serial number": rr_serial,
            "Refresh interval": rr_refresh,
            "Retry interval": rr_retry,
            "Expire limit ": rr_expire, 
            "extract Minimum TTL ": rr_minttl
            }

def get_rdata_AAAA(cursor, dns_packet): 
    """    
    Extract the IPV6 Network Address of the Ressource Record from the RR’s rdata field and return it.

    :param dns_packet: (array of bytes)  The packet received to parse
    :param cursor: (Integer)  The position in packet byte array where the parsing should start
    :returns: A Dictionary with a single key ‘IPV6 address’ whose value is the IPV6 Network Address string of rdata ressource record
    :rtype: Dict

    """
    #retrieves the bytes of the ipV6 address
    ipv6 = dns_packet[cursor:]
    count = 0
    parts = ''
    #creating a loop based on the length of the ipv6
    for i in range(len(ipv6)) :
        #transphormation of the value into hexadecimal
        resolv = f'{ipv6[i]:02x}' 
        parts += resolv
        count += 1
        #add a separation every two bytes
        if count == 2 and i < len(ipv6)-1:
            count = 0
            parts += ":"
    return {"rdata_AAAA_IPV6" : parts}
