#!/usr/bin/env python

import argparse
import os
import sys
from scapy.all import *


def main():
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
            help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap

    if not os.path.isfile(file_name):
        print('"{}" does not exist',format(file_name), file=sys.stderr)
        sys.exit(-1)

    
    #radiotap_pkts = process_pcap(file_name)

if __name__ == "__main__":
    main()
