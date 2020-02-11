#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Log Viewer utilities'


from django.utils.translation import ugettext as _

LOGS_DATABASE = "logs"
MESSAGE_QUEUE_DATABASE = "vulture"

PREDATOR_COLUMNS = (
    'dst_ip', 'src_ip', 'backend_ip', 'frontend_ip', 'server_ip',
    'net_src_ip', 'net_dst_ip', 'http_dst_ip', 'hostname'
)

INTERNAL_COLUMNS = {
    "timestamp": "datetime",
    'log_level': 'string',
    'filename': 'string',
    'message': 'string',
    'source': 'string',
    'node': 'string'
}

DEFAULT_INTERNAL_COLUMNS = {
    "0": {
        "name": "timestamp",
        "width": 2,
        "x": 0
    },
    "2": {
        "name": "log_level",
        "width": 1,
        "x": 2
    },
    "3": {
        "name": "node",
        "width": 1,
        "x": 3
    },
    "4": {
        "name": "filename",
        "width": 2,
        "x": 4
    },
    "6": {
        "name": "source",
        "width": 1,
        "x": 6
    },
    "7": {
        "name": "message",
        "width": 4,
        "x": 7
    }
}

PF_COLUMNS = {
    "action": "string",
    "ttl": "integer",
    "direction": "string",
    "dst_ip": "string",
    "dst_tcp_port": "integer",
    "dst_udp_port": "integer",
    "hostname": "string",
    "if": "string",
    "src_ip": "string",
    "src_tcp_port": "integer",
    "src_udp_port": "integer",
    "time": "datetime",
    "timestamp_app": "double",
    'proto': 'string',
    'len': 'integer',
    'rulenb': 'integer'
}

DEFAULT_PF_COLUMNS = {
    "0": {
        "name": "time",
        "width": 2,
        "x": 0
    },
    "2": {
        "name": "src_ip",
        "width": 2,
        "x": 2
    },
    "4": {
        "name": "dst_ip",
        "width": 2,
        "x": 4
    },
    "6": {
        "name": "dst_tcp_port",
        "width": 1,
        "x": 6
    },
    "7": {
        'name': 'direction',
        'width': 1,
                'x': 7
    },
    "8": {
        "name": "action",
        "width": 1,
        "x": 8
    },
    "9": {
        "name": "if",
        "width": 1,
        "x": 9
    }
}

ACCESS_COLUMNS = {
    "time": "datetime",
    "date_time": "date",
    "bytes_read": "integer",
    "captured_request_cookie": "string",
    "captured_response_cookie": "string",
    "hostname": "string",
    "http_method": "string",
    "http_path": "string",
    "http_get_params": "string",
    "http_version": "string",
    "http_request": "string",
    "http_request_body": "string",
    "http_request_cookies": "string",
    "http_request_content_type": "string",
    "unique_id": "string",
    "status_code": "integer",
    "http_request_time": "integer",
    "http_idle_time": "integer",
    "handshake_time": "integer",
    "http_receive_time": "integer",
    "http_response_time": "integer",
    "unix_timestamp": "date",
    "bytes_received": "integer",
    "active_conn": "integer",
    "backend_name": "string",
    "beconn": "integer",
    "backend_ip": "string",
    "backend_port": "integer",
    "backend_queue": "integer",
    "src_ip": "string",
    "src_port": "integer",
    "frontend_name": "string",
    "feconn": "integer",
    "http_user_agent": "string",
    "frontend_ip": "string",
    "frontend_port": "integer",
    "pid": "integer",
    "retries": "integer",
    "request_count": "integer",
    "server_name": "string",
    "srvconn": "integer",
    "server_ip": "string",
    "server_port": "integer",
    "server_queue": "integer",
    "termination_state": "string",
    "darwin_reputation_error": "integer",
    "darwin_session_error": "integer",
    "darwin_injection_error": "integer",
    "darwin_user_agent_error": "integer",
    "darwin_reputation_score": "integer",
    "darwin_session_score": "integer",
    "darwin_injection_score": "integer",
    "darwin_user_agent_score": "integer",
    "defender_score": "integer",
    "tags": "string",
    "country": "string"
}

ACCESS_TCP_COLUMNS = {
    "time": "datetime",
    "date_time": "date",
    "bytes_read": "integer",
    "unique_id": "string",
    "handshake_time": "integer",
    "unix_timestamp": "date",
    "bytes_received": "integer",
    "active_conn": "integer",
    "backend_name": "string",
    "beconn": "integer",
    "backend_ip": "string",
    "backend_port": "integer",
    "backend_queue": "integer",
    "src_ip": "string",
    "src_port": "integer",
    "frontend_name": "string",
    "feconn": "integer",
    "frontend_ip": "string",
    "frontend_port": "integer",
    "pid": "integer",
    "retries": "integer",
    "request_count": "integer",
    "server_name": "string",
    "srvconn": "integer",
    "server_ip": "string",
    "server_port": "integer",
    "server_queue": "integer",
    "termination_state": "string",
    "darwin_reputation_error": "integer",
    "darwin_reputation_score": "integer",
    "tags": "string",
    "country": "string"
}

DEFAULT_ACCESS_COLUMNS = {
    "0": {
        'name': 'time',
        'width': 2,
        "x": 0
    },
    "2": {
        'name': 'frontend_name',
        'width': 2,
        'x': 2
    },
    "4": {
        'name': 'src_ip',
        'width': 1,
        'x': 4
    },
    "5": {
        "name": "server_ip",
        "width": 1,
        "x": 5
    },
    "6": {
        'name': 'status_code',
        'width': 1,
        'x': 6
    },
    "7": {
        'name': 'bytes_read',
        'width': 1,
        'x': 7
    },
    "8": {
        'name': 'http_method',
        'width': 1,
        'x': 8
    },
    "9": {
        'name': 'http_path',
        'width': 2,
        'x': 9
    },
}

DEFAULT_ACCESS_TCP_COLUMNS = {
    "0": {
        'name': 'time',
        'width': 2,
        "x": 0
    },
    "2": {
        'name': 'frontend_name',
        'width': 2,
        'x': 2
    },
    "4": {
        'name': 'src_ip',
        'width': 1,
        'x': 4
    },
    "5": {
        "name": "server_ip",
        "width": 1,
        "x": 5
    },
    "6": {
        'name': 'bytes_read',
        'width': 1,
        'x': 6
    }
}

IMPCAP_COLUMNS = {
    "time": "datetime",
    "frontend_name": "string",
    "net_bytes_total": "integer",
    "eth_src": "string",
    "eth_dst": "string",
    "eth_tag": "integer",
    "eth_len": "integer",
    "eth_type": "integer",
    "eth_typestr": "string",
    "llc_dsap": "integer",
    "llc_ssap": "integer",
    "llc_ctrl": "integer",
    "snap_oui": "integer",
    "snap_ethtype": "integer",
    "net_src_ip": "string",
    "net_dst_ip": "string",
    "ip_ihl": "integer",
    "net_ttl": "integer",
    "ip_proto": "integer",
    "ipx_transctrl": "integer",
    "ipx_type": "integer",
    "ipx_dest_net": "integer",
    "ipx_src_net": "integer",
    "ipx_dest_node": "string",
    "ipx_src_node": "string",
    "ipx_dest_socket": "integer",
    "ipx_src_socket": "integer",
    "ip6_route_seg_left": "integer",
    "ip6_frag_offset": "integer",
    "ip6_frag_more": "boolean",
    "ip6_frag_id": "integer",
    "arp_hwtype": "integer",
    "arp_ptype": "integer",
    "arp_op": "integer",
    "arp_hwsrc": "string",
    "arp_hwdst": "string",
    "arp_psrc": "string",
    "arp_pdst": "string",
    "rarp_hwtype": "integer",
    "rarp_ptype": "integer",
    "rarp_op": "integer",
    "rarp_hwsrc": "string",
    "rarp_hwdst": "string",
    "rarp_psrc": "string",
    "rarp_pdst": "string",
    "net_icmp_type": "integer",
    "net_icmp_code": "integer",
    "icmp_checksum": "integer",
    "net_src_port": "integer",
    "net_dst_port": "integer",
    "tcp_seq_number": "integer",
    "tcp_ack_number": "integer",
    "tcp_data_length": "integer",
    "net_flags": "string",
    "udp_length": "integer",
    "udp_checksum": "integer",
    "dns_transaction_id": "integer",
    "dns_response_flag": "boolean",
    "dns_opcode": "integer",
    "dns_rcode": "integer",
    "dns_error": "string",
    "dns_qdcount": "integer",
    "dns_ancount": "integer",
    "dns_nscount": "integer",
    "dns_arcount": "integer",
    "dns_names": "dict",
    "smb_version": "integer",
    "smb_ntstatus": "integer",
    "smb_operation": "integer",
    "smb_flags": "string",
    "smb_seqnumber": "integer",
    "smb_processid": "integer",
    "smb_treeid": "integer",
    "smb_userid": "integer",
    "ftp_request": "string",
    "ftp_response": "integer",
    "http_version": "string",
    "http_status_code": "integer",
    "http_method": "string",
    "http_request_uri": "string",
    "http_header_fields": "dict",
    "ctx_src_city_name": "string",
    "ctx_src_country_name": "string",
    "ctx_src_iso_code": "string",
    "ctx_src_latitude": "string",
    "ctx_src_longitude": "string",
    "ctx_src_reputation": "string",
    "ctx_dst_city_name": "string",
    "ctx_dst_country_name": "string",
    "ctx_dst_iso_code": "string",
    "ctx_dst_latitude": "string",
    "ctx_dst_longitude": "string",
    "ctx_dst_reputation": "string"
}

DEFAULT_IMPCAP_COLUMNS = {
    "0": {
        "name": "time",
        "width": 2,
        "x": 0
    },
    "2": {
        "name": "net_src_ip",
        "width": 2,
        "x": 2
    },
    "4": {
        "name": "net_dst_ip",
        "width": 2,
        "x": 4
    },
    "6": {
        "name": "net_src_port",
        "width": 1,
        "x": 6
    },
    "7": {
        'name': 'net_dst_port',
        'width': 1,
        'x': 7
    },
    "8": {
        "name": "darwin_is_alert",
        "width": 2,
        "x": 8
    }
}

MESSAGE_QUEUE_COLUMNS = {
    "date_add": "datetime",
    "node_id": ["foreign_key", "Node"],
    "status": "integer",
    "result": "boolean",
    "action": "string",
    "config": "string",
    "modified": "datetime",
    "internal": "boolean"
}

DEFAULT_MESSAGE_QUEUE_COLUMNS = {
    "0": {
        'name': 'date_add',
        'width': 2,
        "x": 0
    },
    "1": {
        'name': 'modified',
        'width': 2,
        "x": 2
    },
    "2": {
        'name': 'node_id',
        'width': 2,
        'x': 4
    },
    "3": {
        "name": "action",
        "width": 2,
        "x": 6
    },
    "4": {
        'name': 'status',
        'width': 1,
        'x': 8
    },
    "5": {
        'name': 'result',
        'width': 3,
        'x': 9
    },
}

DARWIN_COLUMNS = {
    "evt_id": "string",
    "time": "string",
    "filter": "string",
    "certitude": "integer",
    "details": "string"
}

DARWIN_COLUMNS.update(IMPCAP_COLUMNS)

DEFAULT_DARWIN_COLUMNS = {
    "0": {
        'name': 'time',
        'width': 1,
        "x": 0
    },
    "1": {
        'name': 'frontend',
        'width': 1,
        "x": 1
    },
    "2": {
        'name': 'filter',
        'width': 1,
        "x": 2
    },
    "3": {
        'name': 'net_src_ip',
        'width': 1,
        "x": 3
    },
    "4": {
        'name': 'net_dst_ip',
        'width': 1,
        "x": 4
    },
    "5": {
        'name': 'certitude',
        'width': 1,
        "x": 5
    },
    "6": {
        'name': 'details',
        'width': 1,
        "x": 6
    },
}

AVAILABLE_LOGS = {
    'access': _('Reverse Proxy'),
    'pf': _('Packet Filter'),
    'internal': _('Internal'),
    'impcap': _('Network capture'),
    'message_queue': _('Internal tasks'),
    'darwin': _('Darwin Engine')
}

MAPPING = {
    'access': ACCESS_COLUMNS,
    'access_tcp': ACCESS_TCP_COLUMNS,
    'pf': PF_COLUMNS,
    'internal': INTERNAL_COLUMNS,
    'impcap': IMPCAP_COLUMNS,
    'message_queue': MESSAGE_QUEUE_COLUMNS,
    'darwin': DARWIN_COLUMNS
}

DEFAULT_COLUMNS = {
    'access': DEFAULT_ACCESS_COLUMNS,
    'access_tcp': DEFAULT_ACCESS_TCP_COLUMNS,
    'pf': DEFAULT_PF_COLUMNS,
    'internal': DEFAULT_INTERNAL_COLUMNS,
    'impcap': DEFAULT_IMPCAP_COLUMNS,
    'message_queue': DEFAULT_MESSAGE_QUEUE_COLUMNS,
    'darwin': DEFAULT_DARWIN_COLUMNS
}


MAPPING_GRAPH = {
    "access": {
        "src_ip": "src_ip",
        'dst_ip': 'server_ip'
    },
    "access_tcp": {
        "src_ip": "src_ip",
        'dst_ip': 'server_ip'
    },
    "pf": {
        "src_ip": "src_ip",
        "dst_ip": "dst_ip"
    },
    "impcap": {
        "src_ip": "net_src_ip",
        "dst_ip": "net_dst_ip"
    }
}
