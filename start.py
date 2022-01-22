#!/usr/bin/env python

import argparse
import binascii
import os
import sys
from scapy.all import *

from frame import decrypt_frame


def main():
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
            help='pcap file to parse', required=True)
    parser.add_argument('--key', metavar='<temporal key>',
            help='decryption key (tk)', required=False)
    args = parser.parse_args()

    file_name = args.pcap
    textkey = args.key

    if not os.path.isfile(file_name):
        print('"{}" does not exist',format(file_name), file=sys.stderr)
        sys.exit(-1)

    if textkey == None:
        #key = binascii.a2b_hex("c97c1f67ce371185514a8a19f2bdd52f")  #sample.pcapng key
        key = binascii.a2b_hex("43e3229c41fec8fb81222388c0b5d3d3")  #single.pcapng key
    else:
        key = binascii.a2b_hex(textkey)



    for (pkt_data, pkt_metadata) in RawPcapNgReader(file_name):
        radiotap_pkt = RadioTap(pkt_data)
        decrypt_frame(radiotap_pkt, key)

if __name__ == "__main__":
    main()
