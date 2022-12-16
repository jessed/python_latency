#! /usr/bin/env python3

import datetime
import pcapy
import socket
import os
from math import floor, log10

## Global Variables
DEBUG       = 0
file        = 'sample_captures/2.pcap'


def main():
  #file      = '2.pcap'      # packet capture filename
  count     = 0             # packet number

  # Open packet capture file
  pcap    = pcapy.open_offline(file)

  # read the first packet
  header, payload = pcap.next()

  # Loop through all packets in the capture file
  while header != None:
    # increment the packet counter
    count += 1
  
    # get pcap header information
    t   = header.getts()[0]   # timestamp
    m   = header.getts()[1]   # milliseconds in current second
    l   = header.getlen()     # full packet length
    c   = header.getcaplen()  # truncated packet length
    ts  = combine(t, m)       # create full timestamp
  
    # Skip the first packet in the pcap file
    if payload[0:6].hex() == '000000000000':
      header, payload = pcap.next()
  
  
    # process packet
#    if l > 150:
    # deteremine ethernet type (with or without 802.1q header)
    etherType = payload[12:14]
  
    if etherType.hex() == '0800':
      pkt = get_pkt_data_no_vlan(payload)
    elif etherType.hex() == '8100':
      pkt = get_pkt_data_with_vlan(payload)
    else:
      print(f"ERROR: Ethernet type '{etherType.hex()}' unknown")
  
    # If data is present, show it
    if pkt['dataBytes'] != None:
      # extract the first line of the HTTP data (request/response)
      request = pkt['dataBytes'].decode('UTF-8').splitlines()[0]
  
      # print packet details + the first line of the HTTP data
      print('%f %15s -> %15s  %10d, %10d: %s' % ( ts, pkt['sa'], pkt['da'], pkt['seq'], pkt['ack'], request))
  
  
    # read the next packet
    header, payload = pcap.next()



##
## Functions
##

# Create float (decimal) using math module (faster than from strings)
# (No, I don't actually understand the math)
def combine(t, m):
  if m == 0:
    return t
  return t + m * 10**-(floor(log10(m))+1)


def to_alpha(value):
  text = value.decode('UTF-8')
  return(text)

def get_pkt_data_no_vlan(payload):
  headers = {}
  headers['hdrLen'] = 0

  # MAC headers - starting index: 0
  headers['dmac']       = payload[0:6].hex()
  headers['smac']       = payload[6:12].hex()
  headers['eth_type']   = payload[12:14].hex()
  headers['hdrLen']     += 14

  # IP headers - starting index: 14
  # Only IPv4 supported at this time
  headers['ip_ver']     = int.from_bytes(payload[14:15], 'big') >> 4                # IP version
  headers['ip_len']     = (int.from_bytes(payload[14:15], 'big') & 0b00001111) * 4  # IP header length
  headers['tot_len']    = int.from_bytes(payload[16:18], 'big')                     # IP total length
  headers['sa']         = socket.inet_ntoa(payload[26:30])                          # IP source address
  headers['da']         = socket.inet_ntoa(payload[30:34])                          # IP source address
  headers['hdrLen']     += headers['ip_len']

  # TCP headers - starting index: 38
  headers['seq']        = int.from_bytes(payload[38:42], 'big')
  headers['ack']        = int.from_bytes(payload[42:46], 'big')
  headers['tcpHdrLen']  = (int.from_bytes(payload[46:47], 'big') >> 4) * 4          # TCP header length
  headers['hdrLen']     += headers['tcpHdrLen']

  ## Extract the TCP segment data
  # starting index of tcp segment
  headers['dataStart']  = headers['hdrLen']

  # terminating boundary of tcp segment
  headers['dataEnd']    = headers['dataStart'] + (headers['tot_len'] - headers['hdrLen'] + 1)

  if DEBUG:
    print(f"DEBUG: total_len: {headers['tot_len']}, ipHdr: {headers['ip_len']}, tcpHdr: {headers['tcpHdrLen']}, headerLen: {headers['hdrLen']}\n")

  # extract the data if present, otherwise assign an empty string to headers['dataBytes']
  if headers['dataStart'] < headers['dataEnd']:
    headers['dataBytes']  = payload[headers['dataStart']:headers['dataEnd']]
  else:
    headers['dataBytes'] = None 

	
  # return the populated collection
  return(headers)
  

def get_pkt_data_with_vlan(payload):
  headers = {}
  headers['hdrLen'] = 0

  # MAC headers
  headers['dmac']       = payload[0:6].hex()
  headers['smac']       = payload[6:12].hex()
  headers['eth_type']   = payload[12:14].hex()
  headers['hdrLen']     += 14

  # 802.1q header adds four bytes to header length
  headers['vlan']       = int.from_bytes(payload[14:16], 'big') & 0b0000111111111111  # vlan id
  headers['hdrLen']     += 4

  # IP headers
  # Only IPv4 supported at this time
  headers['ip_ver']     = int.from_bytes(payload[18:19], 'big') >> 4                # IP version
  headers['ip_len']     = (int.from_bytes(payload[18:19], 'big') & 0b00001111) * 4  # IP header length
  headers['tot_len']    = int.from_bytes(payload[20:22], 'big')                     # IP total length
  headers['sa']         = socket.inet_ntoa(payload[30:34])                          # IP source address
  headers['da']         = socket.inet_ntoa(payload[34:38])                          # IP source address
  headers['hdrLen']     += headers['ip_len']

  # TCP headers
  headers['seq']        = int.from_bytes(payload[42:46], 'big')
  headers['ack']        = int.from_bytes(payload[46:50], 'big')

  headers['tcpHdrLen']  = (int.from_bytes(payload[50:51], 'big') >> 4) * 4          # TCP header length
  headers['hdrLen']     += headers['tcpHdrLen']

  ## Extract the TCP segment data

  # starting index of tcp segment
  headers['dataStart']  = headers['hdrLen']

  # terminating boundary of tcp segment
  headers['dataEnd']    = headers['dataStart'] + (headers['tot_len'] - headers['hdrLen'] + 1)

  # extract the data if present, otherwise assign an empty string to headers['dataBytes']
  if headers['dataStart'] < headers['dataEnd']:
    headers['dataBytes']  = payload[headers['dataStart']:headers['dataEnd']]
  else:
    headers['dataBytes'] = None
  return(headers)


##
## Main
##


if __name__ == '__main__':
  main()
