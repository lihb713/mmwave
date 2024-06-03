import ctypes as ct


ETHER_ADDR_LEN = 6
ETHER_HEADER_LEN = 14
UDP_HEADER_LEN = 8


class SniffEthernet(ct.Structure):
    _fields_ = [
        ('etherDHost', ct.c_ubyte * ETHER_ADDR_LEN),
        ('etherSHost', ct.c_ubyte * ETHER_ADDR_LEN),
        ('etherType', ct.c_ushort)
    ]


class SniffIp(ct.Structure):
    _fields_ = [
        ('ipVHL', ct.c_ubyte),  # version && head
        ('ipTOS', ct.c_ubyte),  # type of service
        ('ipLen', ct.c_ushort),  # length
        ('ipId', ct.c_ushort),
        ('ipOff', ct.c_ushort),  # packet offset
        ('ipTTL', ct.c_ubyte),  # time to live
        ('ipP', ct.c_ubyte),  # protocol
        ('ipSum', ct.c_ushort),  # sum check
        # ('ipSrc', struct in_addr)
        # ('ipDst', struct in_addr)
    ]


class SniffUdp(ct.Structure):
    _fields_ = [
        ('udpSPort', ct.c_ushort),
        ('udpDPort', ct.c_ushort),
        ('udpLen', ct.c_ushort),
        ('udpSum', ct.c_ushort)
    ]

def IP_HL(ip):
    return ip.ipVHL & 0x0f

def IP_V(ip):
    return ip.ipVHL >> 4