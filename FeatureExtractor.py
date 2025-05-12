from scapy.all import PcapReader, IP, TCP, UDP, DNS, Raw, DNSQR, rdpcap
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import BOOTP
from scapy.contrib.coap import CoAP
from scapy.contrib.mqtt import MQTT
import pandas as pd
from collections import defaultdict
import numpy as np
from statistics import mode


def extract_flow_features(pcap_file, time_interval=1):
    flows = defaultdict(list)
    features = []

    with PcapReader(pcap_file) as packets:
    #with rdpcap(pcap_file) as packets:
        current_time = 0
        for packet in packets:
            if IP in packet:
                mac_src = packet[Ether].src
                mac_dst = packet[Ether].dst
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                timestamp = packet.time

                if timestamp - current_time >= time_interval:
                    # Process and reset flows
                    features.extend(process_flows(flows))
                    flows.clear()
                    current_time = timestamp

                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    header_length = len(packet[TCP])
                    tcp_window_size = packet[TCP].window
                    tcp_options = packet[TCP].options if packet[TCP].options else []
                elif UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    flags = 0
                    header_length = len(packet[UDP])
                    tcp_window_size = 0
                    tcp_options = []
                else:
                    sport = dport = flags = header_length = tcp_window_size = 0
                    tcp_options = []

                flow_key = (mac_src,mac_dst,ip_src, ip_dst, sport, dport, protocol)
                flows[flow_key].append((timestamp, len(packet), flags, header_length, tcp_window_size, tcp_options, packet))

        # Process remaining flows
        features.extend(process_flows(flows))

    
    return features




def process_flows(flows):
    features = []

    for flow_key, packets in flows.items():
        mac_src,mac_dst,ip_src, ip_dst, sport, dport, protocol = flow_key
        timestamps, lengths, flags, header_lengths, tcp_window_sizes, tcp_options, raw_packets = zip(*packets)
        
        flow_duration = max(timestamps) - min(timestamps)
        total_packets = len(packets)
        total_bytes = sum(lengths)
        flow_std = np.std(lengths)
        flow_var = np.var(lengths)

        packet_lengths = lengths
        
        src_bytes = sum(l for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_src)
        dst_bytes = sum(l for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_dst)
        
        iat = np.diff(timestamps)

        flow_iat = float(np.mean(np.array(iat, dtype=float))) if len(iat) > 0 else 0
        forward_iat = np.diff([ts for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_src])
        backward_iat = np.diff([ts for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_dst])
        forward_iat_mean= float(np.mean(np.array(forward_iat, dtype=float))) if len(forward_iat) > 0 else 0
        backward_iat_mean= float(np.mean(np.array(backward_iat, dtype=float))) if len(backward_iat) > 0 else 0
        f_packets = len([1 for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_src])
        b_packets = len([1 for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_dst])
        
        forward_packet_size_dist = [l for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_src]
        backward_packet_size_dist = [l for ts, l, f, h, w, to, rp in packets if rp[IP].src == ip_dst]
        header_length_mean = np.mean(header_lengths)
        packet_rate = total_packets / flow_duration if flow_duration > 0 else 0
        byte_rate = total_bytes / flow_duration if flow_duration > 0 else 0
        flow_rate = packet_rate
        syn_flag_count = sum(1 for f in flags if f & 0x02)
        fin_flag_count = sum(1 for f in flags if f & 0x01)
        rst_flag_count = sum(1 for f in flags if f & 0x04)
        psh_flag_count = sum(1 for f in flags if f & 0x08)
        urg_flag_count = sum(1 for f in flags if f & 0x20)
        ece_flag_count = sum(1 for f in flags if f & 0x40)
        cwr_flag_count = sum(1 for f in flags if f & 0x80)
        first_packet_time = min(timestamps)
        last_packet_time = max(timestamps)
        flow_active_mean = np.mean(np.array(iat, dtype=float)) if len(iat) > 0 else 0
        flow_active_min = np.min(np.array(iat, dtype=float)) if len(iat) > 0 else 0
        flow_active_max = np.max(np.array(iat, dtype=float)) if len(iat) > 0 else 0
        flow_active_std = np.std(np.array(iat, dtype=float)) if len(iat) > 0 else 0
        flow_idle_times = [iat[i] - iat[i-1] for i in range(1, len(iat))]
        flow_idle_mean = np.mean(np.array(flow_idle_times, dtype=float)) if len(flow_idle_times) > 0 else 0
        flow_idle_min = np.min(np.array(flow_idle_times, dtype=float)) if len(flow_idle_times) > 0 else 0
        flow_idle_max = np.max(np.array(flow_idle_times, dtype=float)) if len(flow_idle_times) > 0 else 0
        flow_idle_std = np.std(np.array(flow_idle_times, dtype=float)) if len(flow_idle_times) > 0 else 0
        dscp_values = [packet[IP].tos for packet in raw_packets]
        ecn_values = [packet[IP].tos & 0x03 for packet in raw_packets]
        fragmented_packets = sum(1 for packet in raw_packets if packet[IP].flags & 0x1)
        fragmentation_offsets = [packet[IP].frag for packet in raw_packets if packet[IP].frag != 0]

        
        # Handling specific protocols for DNS and HTTP

        http_methods = [packet[Raw].load.decode(errors='ignore').split(' ')[0] for packet in raw_packets if Raw in packet and packet[Raw].load.decode(errors='ignore').split(' ')[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']]
        
        try:
            http_methods_len=len(http_methods) #
        except:
            http_methods_len=None
        try:
            http_methods_Ulen=len(np.unique(http_methods)) #
        except:
            http_methods_Ulen=None
        try:
            http_methods_mode=mode(http_methods) #
        except:
            http_methods_mode=None

        #count
        http_GET_count = http_methods.count('GET') if 'GET' in http_methods else None
        http_PUT_count =http_methods.count('PUT') if 'PUT' in http_methods else None
        http_POST_count =http_methods.count('POST') if 'POST' in http_methods else None
        http_DELETE_count = http_methods.count('DELET') if 'DELET' in http_methods else None
        http_PATCH_count =http_methods.count('PATCH') if 'PATCH' in http_methods else None
        http_HEAD_count =http_methods.count('HEAD') if 'HEAD' in http_methods else None
        http_OPTIONS_count =http_methods.count('OPTIONS') if 'OPTIONS' in http_methods else None
        http_TRACE_count =http_methods.count('TRACE') if 'TRACE' in http_methods else None
        http_CONNECT_count =http_methods.count('CONNECT') if 'CONNECT' in http_methods else None       
        
        http_status_codes = [int(packet[Raw].load.decode(errors='ignore').split(' ')[1]) for packet in raw_packets if Raw in packet and packet[Raw].load.decode(errors='ignore').split(' ')[0] == 'HTTP/1.1']
        
        try:
            http_status_codes_len = len(http_status_codes)
        except:
            http_status_codes_len = None

        try:    
            http_status_codes_mode= mode(http_status_codes)
        except:
            http_status_codes_mode= None

        try:    
            http_status_codes_Ulen= len(np.unique(http_status_codes))
        except:
            http_status_codes_Ulen= None
        

        dns_query_types = [packet[DNS].qd.qtype for packet in raw_packets if DNS in packet and packet.haslayer(DNSQR) and packet.qr == 0]     
        
        try:
            dns_query_types_len = len(dns_query_types)
        except:
            dns_query_types_len = None

        try:    
            dns_query_types_mode = mode(dns_query_types)
        except:
            dns_query_types_mode = None

        try:    
            dns_query_types_Ulen = len(np.unique(dns_query_types))
        except:
            dns_query_types_Ulen = None
        
        
        
        dns_response_codes = [packet[DNS].rcode for packet in raw_packets if DNS in packet and packet[DNS].qr == 1]
        try:
            dns_response_codes_len = len(dns_response_codes)
        except:
            dns_response_codes_len = None

        try:    
            dns_response_codes_mode = mode(dns_response_codes)
        except:
            dns_response_codes_mode = None

        try:    
            dns_response_codes_Ulen = len(np.unique(dns_response_codes))
        except:
            dns_response_codes_Ulen = None



        # mqtt_message_types = [packet[Raw].load[0] >> 4 for packet in raw_packets if Raw in packet and len(packet[Raw].load) > 0 and packet[TCP].dport == 1883]
        mqtt_message_types = []
        for packet in raw_packets:
            if Raw in packet and len(packet[Raw].load) > 0:
                if packet.haslayer(TCP) and packet[TCP].dport == 1883:
                    mqtt_message_types.append(packet[Raw].load[0] >> 4)
        
        try:
            mqtt_message_types_len=len(mqtt_message_types)
        except:
            mqtt_message_types_len=None

        try:
            mqtt_message_types_mode=mode(mqtt_message_types)
        except:
            mqtt_message_types_mode=None

        try:
            mqtt_message_types_Ulen=len(np.unique(mqtt_message_types))
        except:
            mqtt_message_types_Ulen=None

        # amqp_packets = [packet[Raw] for packet in raw_packets if Raw in packet and b'AMQP' in bytes(packet[Raw])]
        # amqp_methods = []
        # for packet in raw_packets:
        #     if Raw in packet and packet.haslayer(TCP) and packet[TCP].dport == 5672:
        #         amqp_methods.append(packet[Raw].load.decode(errors='ignore').split(' ')[0])
        # coap_message_types = []
        # for packet in raw_packets:
        #     if Raw in packet and UDP in packet and packet[UDP].dport == 5683:
        #         try:
        #             coap_message_types.append(packet[Raw].load[0] >> 4)
        #         except (IndexError, TypeError):
        #             pass  # Handle cases where load may not be accessible or does not contain expected data
        #ftp_commands = [packet[Raw].load.decode(errors='ignore').split(' ')[0] for packet in raw_packets if Raw in packet and packet[TCP].dport in [21, 20]]
        # ssh_packets = [packet for packet in raw_packets if Raw in packet and b'SSH' in packet[Raw].load]
        #ssh_messages = [packet[Raw].load[0] for packet in raw_packets if Raw in packet and packet[TCP].dport == 22]
        

        rtsp_methods = []
        for packet in raw_packets:
            if Raw in packet and packet.haslayer(TCP) and packet[TCP].dport == 8554:
                rtsp_methods.append(packet[Raw].load.decode(errors='ignore').split(' ')[0])


        try:
            rtsp_methods_len = len(rtsp_methods)
        except:
            rtsp_methods_len = None
        try:
            rtsp_methods_Ulen = len(np.unique(rtsp_methods))
        except:
            rtsp_methods_Ulen = None
        try:
            rtsp_methods_mode = mode(rtsp_methods)
        except:
            rtsp_methods_mode = None


        rtsp_methods_c_option = rtsp_methods.count('OPTIONS') if 'OPTIONS' in rtsp_methods else None
        rtsp_methods_c_setup = rtsp_methods.count('SETUP') if 'SETUP' in rtsp_methods else None
        rtsp_methods_c_describe = rtsp_methods.count('DESCRIBE') if 'DESCRIBE' in rtsp_methods else None
        rtsp_methods_c_setpara = rtsp_methods.count('SET_PARAMETER') if 'SET_PARAMETER' in rtsp_methods else None
        rtsp_methods_c_record = rtsp_methods.count('RECORD') if 'RECORD' in rtsp_methods else None
        rtsp_methods_c_teardown = rtsp_methods.count('TEARDOWN') if 'TEARDOWN' in rtsp_methods else None
        rtsp_methods_c_redirect = rtsp_methods.count('REDIRECT') if 'REDIRECT' in rtsp_methods else None
        rtsp_methods_c_play = rtsp_methods.count('PLAY') if 'PLAY' in rtsp_methods else None
        rtsp_methods_c_pause = rtsp_methods.count('PAUSE') if 'PAUSE' in rtsp_methods else None

        # xmpp_packets = [packet for packet in raw_packets if Raw in packet and (b'xmpp' in packet[Raw].load.lower())]
        # xmpp_stanzas = [packet[Raw].load.decode(errors='ignore').split(' ')[0] for packet in raw_packets if Raw in packet and packet[TCP].dport == 5222]
        
        # dhcp_message_types = []
        # for packet in raw_packets:
        #     if BOOTP in packet:
        #         try:
        #             dhcp_options = packet[BOOTP].options
        #             for option in dhcp_options:
        #                 if isinstance(option, tuple) and len(option) >= 2 and option[0] == 'message-type':
        #                     dhcp_message_types.append(option[1])
        #         except Exception as e:
        #             print(f"Error processing DHCP packet: {e}")
        #snmp_message_types = [packet[SNMP].PDUtype for packet in raw_packets if SNMP in packet]
        
        # Additional metrics
        rtt = sum([packet[TCP].ack for packet in raw_packets if TCP in packet and 'A' in packet[TCP].flags]) / total_packets if total_packets > 0 else 0
        handshake_duration = (max(timestamps) - min(timestamps)) if syn_flag_count > 0 else 0
        retransmission_count = sum(1 for packet in raw_packets if TCP in packet and packet[TCP].flags == 'R')
        duplicate_ack_count = sum(1 for packet in raw_packets if TCP in packet and packet[TCP].flags == 'A' and packet[TCP].ack != 0)
        checksum_errors = sum(1 for packet in raw_packets if IP in packet and packet[IP].chksum != packet[IP].__class__(bytes(packet[IP])).chksum)
        malformed_packets = sum(1 for packet in raw_packets if packet[IP].len != len(packet))

        # Throughput and Jitter
        forward_throughput = src_bytes / flow_duration if flow_duration > 0 else 0
        backward_throughput = dst_bytes / flow_duration if flow_duration > 0 else 0
        forward_jitter = np.std(np.array(forward_iat, dtype=float)) if len(forward_iat) > 0 else 0
        backward_jitter = np.std(np.array(backward_iat, dtype=float)) if len(backward_iat) > 0 else 0

        # Flow Entropy and Burstiness
        flow_entropy = -np.sum([p / total_packets * np.log2(p / total_packets) for p in packet_lengths])
        flow_burstiness = np.std(np.array(iat, dtype=float)) if len(iat) > 0 else 0

        # Payload features
        payloads = [len(packet[Raw].load) for packet in raw_packets if Raw in packet]
        payload_length = np.sum(payloads)
        payload_entropy = -np.sum([p / payload_length * np.log2(p / payload_length) for p in payloads]) if payload_length > 0 else 0
        payload_byte_distribution = np.bincount(payloads) / payload_length if payload_length > 0 else [0]

        # Multicast/Broadcast Packet Count
        multicast_packet_count = sum(1 for packet in raw_packets if IP in packet and packet[IP].dst.startswith("224."))
        broadcast_packet_count = sum(1 for packet in raw_packets if IP in packet and packet[IP].dst == "255.255.255.255")

        # Session duration
        session_duration = flow_duration
        session_packet_count = total_packets
        session_byte_count = total_bytes



        #redefined
        #dscp
        try:
            dscp_count=len(dscp_values) #
        except:
            dscp_count=None
        try:
            dscp_mode=mode(dscp_values) #
        except:
            dscp_mode=None
        try:
            dscp_sum=sum(dscp_values) #
        except:
            dscp_sum=None
        try:
            dscp_unique_len=len(np.unique(dscp_values)) #
        except:
            dscp_unique_len=None

        #ecn
        try:
            ecn_count=len(ecn_values) #
        except:
            ecn_count=None
        try:
            ecn_mode=mode(ecn_values) #
        except:
            ecn_mode=None
        try:
            ecn_sum=sum(ecn_values) #
        except:
            ecn_sum=None
        try:
            ecn_unique_len=len(np.unique(ecn_values)) #
        except:
            ecn_unique_len=None

        # backward_packet_size_dist
        try:
            backward_Header_mode=mode(backward_packet_size_dist)
        except:
            backward_Header_mode=None


        # forward_packet_size_dist
        try:
            forward_Header_mode=mode(forward_packet_size_dist)
        except:
            forward_Header_mode=None
       
        
        # tcp_window_sizes
        try:
            tcp_window_size_sum=sum(tcp_window_sizes) #
        except:
            tcp_window_size_sum=None
           

        try:
            tcp_window_size_mean=np.mean(tcp_window_sizes) #
        except:
            tcp_window_size_mean=None
           
        try:
            tcp_window_size_mode=mode(tcp_window_sizes) #
        except:
            tcp_window_size_mode=None

        try:
            packet_lengths_mode = mode(packet_lengths)
        except:
            packet_lengths_mode=None

        
        try:
            header_lengths_sum=sum(header_lengths)
        except:
            header_lengths_sum=None
            
        try:
            header_lengths_mode=mode(header_lengths)
        except:
            header_lengths_mode=None

        try:
            multicast_group_address_lenght=len([packet[IP].dst for packet in raw_packets if IP in packet and packet[IP].dst.startswith("224.")])
        except:
            multicast_group_address_lenght=None

        try:
            multicast_group_address_Ulenght=len(np.unique([packet[IP].dst for packet in raw_packets if IP in packet and packet[IP].dst.startswith("224.")]))
        except:
            multicast_group_address_Ulenght=None



    
        features.append({
            "S_MAC": mac_src,                           # Source MAC
            "D_MAC": mac_dst,                           # Destination MAC
            "FPT": first_packet_time,                   # First Packet Time
            "LPT": last_packet_time,                    # Last Packet Time
            "FD": flow_duration,                        # Flow Duration
            "FAMin": flow_active_min,                   # Flow Active Min
            "FAMean": flow_active_mean,                 # Flow Active Mean
            "FAMax": flow_active_max,                   # Flow Active Max
            "FAStd": flow_active_std,                   # Flow Active Std 
            "FIMean": flow_idle_mean,                   # Flow Idle Mean
            "FIMin": flow_idle_min,                     # Flow Idle Min
            "FIMax": flow_idle_max,                     # Flow Idle Max
            "FIStd": flow_idle_std,                     # Flow Idle Std
            "DSCP_C": dscp_count,                       # DSCP Count
            "DSCP_M": dscp_mode,                        # DSCP Mode
            "DSCP_UV": dscp_unique_len,                 # DSCP Unique Values
            "DSCP_S": dscp_sum,                         # DSCP Sum
            "ECN_C": ecn_count,                         # ECN Count
            "ECN_M": ecn_mode,                          # ECN Mode
            "ECN_UV": ecn_unique_len,                   # ECN Unique Values
            "ECN_S": ecn_sum,                           # ECN Sum
            "FPC": fragmented_packets,                  # Fragmented Packet Count            
            "TPackets": total_packets,                  # Total Packets
            "TBytes": total_bytes,                      # Total Bytes
            "SBytes": src_bytes,                        # Source Bytes
            "DBytes": dst_bytes,                        # Destination Bytes
            "PLM": packet_lengths_mode,                 # Packet Lengths Mode
            "FI": flow_iat,                             # Flow IAT
            "FIAT": forward_iat_mean,                   # Forward IAT
            "BIAT": backward_iat_mean,                  # Backward IAT
            "ForwardPC": f_packets,                     # Forward Packet Count
            "BackwardPC": b_packets,                    # Backward Packet Count
            "FlowR": flow_rate,                         # Flow Rate
            "FlowStd": flow_std,                        # Flow Standard Deviation
            "FlowV": flow_var,                          # Flow Variance
            "FH_M": forward_Header_mode,                # Forward Header Mode
            "BH_M": backward_Header_mode,               # Backward Header Mode, Forward Average Packet Size, Backward Average Packet Size
            "FAPS": np.mean(forward_packet_size_dist) if forward_packet_size_dist else 0,
            "BAPS": np.mean(backward_packet_size_dist) if backward_packet_size_dist else 0,
            "FBPP": total_bytes / total_packets if total_packets > 0 else 0,    # Flow Bytes per Packet
            "FFD": forward_iat_mean,                    # Forward Flow Duration
            "Proto": protocol,                          # Protocol
            "SIP": ip_src,                              # Source IP
            "DIP": ip_dst,                              # Destination IP
            "SPort": sport,                             # Source Port
            "DPort": dport,                             # Destination Port
            "SDuration": session_duration,              # Session Duration
            "SPC": session_packet_count,                # Session Packet Count
            "SBCount": session_byte_count,              # Session Byte Count
            "BytesPS": byte_rate,                       # Bytes per Second
            "PacketsPS": packet_rate,                   # Packets per Second
            "RTT": rtt,                                 # Round Trip Time
            "HL_Sum" : header_lengths_sum,              # Header Lengths Sum
            "HL_Mode" : header_lengths_mode,            # Header Lengths Mode
            "HL_mean": header_length_mean,              # Header Length Mean
            "SYN_FC":syn_flag_count,                    # SYN Flag Count
            "FIN_FC":fin_flag_count,                    # FIN Flag Count
            "RST_FC":rst_flag_count,                    # RST Flag Count
            "PSH_FC":psh_flag_count,                    # PSH Flag Count
            "URG_FC":urg_flag_count,                    # URG Flag Count
            "ECE_FC": ece_flag_count,                   # ECE Flag Count
            "CWR_FC": cwr_flag_count,                   # CWR Flag Count
            "TCP_HD": handshake_duration,               # TCP Handshake Duration
            "RCount": retransmission_count,             # Retransmission Count
            "DACount": duplicate_ack_count,             # Duplicate ACK Count
            "CE": checksum_errors,                      # Checksum Errors
            "MPackets": malformed_packets,              # Malformed Packets
            "FThroughput": forward_throughput,          # Forward Throughput
            "BThroughput": backward_throughput,         # Backward Throughput
            "FJitter": forward_jitter,                  # Forward Jitter
            "BJitter": backward_jitter,                 # Backward Jitter
            "FBurst": flow_burstiness,                  # Flow Burstiness
            "FEntropy": flow_entropy,                   # Flow Entropy
            "PIA_Var": np.var(np.array(iat, dtype=float)) if len(iat) > 0 else 0, #Packet Inter-Arrival Variance
            "PL": payload_length,                       # Payload Length
            "PEntropy": payload_entropy,                # Payload Entropy
            "MP_Count": multicast_packet_count,         # Multicast Packet Count
            "BP_Count": broadcast_packet_count,         # Broadcast Packet Count
            "MGA_L": multicast_group_address_lenght,    # Multicast Group Address Lenght
            "MGA_UL": multicast_group_address_Ulenght,  # Multicast Group Address Unique Lenght
            "SIT": min(timestamps),                     # Session Initiation Time
            "STT": max(timestamps),                     # Session Termination Time
            "FIPD_Var": np.var(np.array(forward_iat, dtype=float)) if len(forward_iat) > 0 else 0, # Forward Inter-Packet Delay Variance
            "BIPD_Var": np.var(np.array(backward_iat, dtype=float)) if len(backward_iat) > 0 else 0, # Backward Inter-Packet Delay Variance
            "TCPWS_Sum": tcp_window_size_sum,           # TCP Window Size Sum
            "TCPWS_Mean": tcp_window_size_mean,         # TCP Window Size Mean
            "TCPWS_Mode": tcp_window_size_mode,         # TCP Window Size Mode
            "HTTPRM_L": http_methods_len,               # HTTP Request Methods Lenght
            "HTTPRM_UL": http_methods_Ulen,             # HTTP Request Methods Unique Lenght
            "HTTPRM_M": http_methods_mode,              # HTTP Request Methods Mode
            "HTTPGetC" : http_GET_count,                # HTTP GET Count
            "HTTPPutC" : http_PUT_count,                # HTTP PUT Count
            "HTTPPostC" : http_POST_count,              # HTTP POST Count
            "HTTPDeletC" : http_DELETE_count,           # HTTP DELET Count
            "HTTPPatchC" : http_PATCH_count,            # HTTP PATCH Count
            "HTTPHeadC" : http_HEAD_count,              # HTTP Head Count
            "HTTPOptC" : http_OPTIONS_count,            # HTTP Option Count
            "HTTPTraceC" : http_TRACE_count,            # HTTP Trace Count
            "HTTPConC" : http_CONNECT_count,            # HTTP connect Count
            "HTTP_SCL": http_status_codes_len,          # HTTP Status Codes Lenght
            "HTTP_SCUL:": http_status_codes_Ulen,       # HTTP Status Codes Unique Lenght
            "HTTP_SCM": http_status_codes_mode,         # HTTP Status Codes Mode
            "DNSQTL": dns_query_types_len,              # DNS Query Types Lenght
            "DNS_QTUL": dns_query_types_Ulen,           # DNS Query Types Unique Lenght
            "DNS_QTM": dns_query_types_mode,            # DNS Query Types Mode
            "DNS_RCL": dns_response_codes_len,          # DNS Response Codes Lenght
            "DNS_RCUL": dns_response_codes_Ulen,        # DNS Response Codes Unique Lenght         
            "DNS_RCM": dns_response_codes_mode,         # DNS Response Codes Mode
            "MQTT_MTL": mqtt_message_types_len,         # MQTT Message Types Lenght
            "MQTT_MTUL": mqtt_message_types_Ulen,       # MQTT Message Types Unique Lenght
            "MQTT_MTM": mqtt_message_types_mode,        # MQTT Message Types Mode
            "RTSP_ML": rtsp_methods_len,                # RTSP Methods Lenght       
            "RTSP_MUL": rtsp_methods_Ulen,              # RTSP Methods Unique Lenght
            "RTSP_MM": rtsp_methods_mode,               # RTSP Methods Mode
            "RTSP_OptionC": rtsp_methods_c_option,      # RTSP Option Count
            "RTSP_SETUPC": rtsp_methods_c_setup,        # RTSP Setup Count
            "RTSP_DESCC": rtsp_methods_c_describe,      # RTSP DESCRIBE Count
            "RTSP_SPC": rtsp_methods_c_setpara,         # RTSP SET_Parameter Count
            "RTSP_RecordC": rtsp_methods_c_record,      # RTSP Record Count
            "RTSP_TeardownC": rtsp_methods_c_teardown,  # RTSP Teardown Count
            "RTSP_RedirectC": rtsp_methods_c_redirect,  # RTSP Redirect Count
            "RTSP_PlayC": rtsp_methods_c_play,          # RTSP Play Count
            "RTSP_PauseC": rtsp_methods_c_pause         # RTSP Pause Count
        })
    return features