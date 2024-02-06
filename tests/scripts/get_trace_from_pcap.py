#!/usr/bin/env python3
#
#
# Parse an OpenVPN handshake pcap file, extract relevant fields from the json,
# and return a compact representation of the packets in the handshake that can be
# used for testing minivpn's implementation.
# This script depends on tshark.
# 
# Usage: 
#
# There are two subcommands: json | sequence
# - json dumps the json representation of a subset of the handshake
# - sequence outputs a test sequence that can be used to write unit tests.
# 
# Examples:
# 
# python3 get_trace_from_pcap.py good-handshake.pcapng json | jq
# python3 get_trace_from_pcap.py good-handshake.pcapng sequence | nl
#

import json
import subprocess
import sys

opcodes = {
    '0x01': 'CONTROL_HARD_RESET_CLIENT_V1',
    '0x02': 'CONTROL_HARD_RESET_SERVER_V1',
    '0x03': 'CONTROL_SOFT_RESET_V1',
    '0x04': 'CONTROL_V1',
    '0x05': 'ACK_V1',
    '0x06': 'DATA_V1',
    '0x07': 'CONTROL_HARD_RESET_CLIENT_V2',
    '0x08': 'CONTROL_HARD_RESET_SERVER_V2',
    '0x09': 'DATA_V2'
}

def process_tshark_output(data):
    packets = []
    ips = {}

    for packet in data:
        ip = packet['_source']['layers']['ip']
        udp = packet['_source']['layers']['udp']

        # TODO: do sanity check here and verify all of them belong to the same UDP stream.

        openvpn = packet['_source']['layers']['openvpn']

        time_relative = udp['Timestamps']['udp.time_relative']
        time_delta = udp['Timestamps']['udp.time_delta']

        ip_src = ip['ip.src']
        if len(ips) == 0:
            ips[ip_src] = 'client'

        ip_dst = ip['ip.dst']
        if len(ips) == 1:
            ips[ip_dst] = 'server'

        packets.append({
            'time_relative': time_relative,
            'time_delta': time_delta,
            'from': ips[ip_src],
            'to': ips[ip_dst],
            'openvpn': openvpn,
        })

    return packets


def sequence_from_packets(packets):
    for i, packet in enumerate(packets):
        if packet['from'] == 'client':
            dir = '>'
        else:
            dir = '<'

        packet_id = packet['openvpn'].get('openvpn.mpid', 0)
        opcode = opcodes[packet['openvpn']['openvpn.type_tree']['openvpn.opcode']]

        acks = []
        ack_len = packet['openvpn'].get('openvpn.mpidarraylength')
        if ack_len is not None and int(ack_len) != 0:
            acks = packet['openvpn']['Packet-ID Array']['openvpn.mpidarrayelement']

        if len(acks) > 0:
            ack_str = ','.join([str(ack) for ack in acks])
        else:
            ack_str = ''

        try:
            # get the inter-arrival time until the next packet in the
            # handshake arrives. in the unit tests, we specify this as IAT 
            # for a TestPacket, since we want the packet writer to sleep
            # for this amount of time.
            next_packet_ts = float(packets[i+1].get('time_delta')) * 1000
        except IndexError:
            next_packet_ts = 0

        print(f"{dir} [{packet_id}] {opcode} (acks:{ack_str}) +{next_packet_ts:.8f}ms")


if __name__ == "__main__":
    pcap = sys.argv[1]
    subcmd = sys.argv[2]

    command = f"tshark -r {pcap} -T json --no-duplicate-keys"
    out = subprocess.check_output(command, shell=True)
    output_str = out.decode('utf-8')
    data = json.loads(output_str)
    packets = process_tshark_output(data)

    if subcmd == "json":
        print(json.dumps(packets))
        sys.exit(0)

    if subcmd == "sequence":
        sequence_from_packets(packets)
