
class Protocol:
    def __init__(self):
        # basic info
        self.time = ''
        self.src_mac = ''
        self.des_mac = ''
        self.protocol = ''
        self.src_ip = ''
        self.des_ip = ''
        self.len = ''
        self.src_port = ''
        self.des_port = ''
        self.info = ''
        self.ip_payload_len = ''
        self.tcp_header = ''
        self.payload_len = ''
        self.segment = ''
        self.seq = ''
        # more info
        self.data = []
        self.assemble_data = b''
        self.assemble_payload_len = ''
        self.frame = []
        self.ok = False

