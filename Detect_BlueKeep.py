#!/usr/bin/env python3

import time
import pyshark
import keyboard # run with sudo in linux, sudo python3 -m pip install keyboard
import multiprocessing
import threading
import datetime

# global var
iface_name = 'VMware Network Adapter VMnet8'
bpf_filter_string = 'tcp port 3389' # capture filter rdp traffic
display_filter_string = 'rdp || tcp.flags.fin==1 || tcp.flags.reset==1 || tcp.analysis.window_full'
log_file_name = 'bluekeep.log'
rdp_connection = {} #{"ip_client -> ip_server" : {"status_connected":"True", "ms_t120":False , "cookie_random":set(), "ttl_cookie":200, "tcp_windows_full":0, "time":"0h00m00s", "client_port":"", "server_port":""}, }
ttl_rdp_countdown = True

def count_down(time_s, key_string):
    global ttl_rdp_countdown

    if key_string == 'program':
        time.sleep(time_s)
        return True
    elif key_string == 'ttl_rdp':
        while True:
            if ttl_rdp_countdown == True:
                time.sleep(time_s)
                ttl_rdp_countdown = False

def get_info_packet(packet):
    source_ip, dest_ip, src_port, dst_port, date_time_packet = '', '', '', '', ''
    # ip source
    if 'ip' in packet and 'src' in packet.ip.field_names:
        source_ip = str(packet.ip.src)
    elif 'ipv6' in packet and 'src' in packet.ipv6.field_names:
        source_ip = str(packet.ipv6.src)
    elif 'eth' in  packet:
        if 'src_oui_resolved' in packet.eth.field_names:
            source_ip += str(packet.eth.src_oui_resolved)
        if 'src' in packet.eth.field_names:
            source_ip = '{} ({})'.format(source_ip, str(packet.eth.src))
    # ip dest
    if 'ip' in packet and 'dst' in packet.ip.field_names:
        dest_ip = str(packet.ip.dst)
    elif 'ipv6' in packet and 'dst' in packet.ipv6.field_names:
        dest_ip = str(packet.ipv6.dst)
    elif 'eth' in  packet:
        if 'dst_oui_resolved' in packet.eth.field_names:
            dest_ip += str(packet.eth.dst_oui_resolved)
        if 'dst' in packet.eth.field_names:
            dest_ip = '{} ({})'.format(dest_ip, str(packet.eth.dst))
    # port
    if 'tcp' in packet:
        if 'srcport' in packet.tcp.field_names:
            src_port = str(packet.tcp.srcport)
        if 'dstport' in packet.tcp.field_names:
            dst_port = str(packet.tcp.dstport)
    # date time sniff
    if 'sniff_time' in dir(packet):
        date_time_packet = str(packet.sniff_time)
    
    return source_ip, dest_ip, src_port, dst_port, date_time_packet

# signature for CVE-2019-0708
def matched_signature_BlueKeep(packet):
    global rdp_connection
    # RDP packet
    if 'rdp' in packet:
        # requet cookie
        if 'rt_cookie' in packet.rdp.field_names:
            src_ip, dst_ip, src_port, dst_port, date_time_packet = get_info_packet(packet)
            ip_pair = "{} -> {}".format(src_ip, dst_ip)
            rt_cookie = str(packet.rdp.rt_cookie)
            cookie = rt_cookie[rt_cookie.index("=")+1:]
            if ip_pair not in rdp_connection:
                rdp_connection[ip_pair] = {"status_connected":True, 
                                           "ms_t120":False, 
                                           "cookie_random":set([cookie]) if len(cookie) == 7 else set(),
                                           "ttl_cookie":200,
                                           "tcp_windows_full":0, 
                                           "start_time":date_time_packet,
                                           "client_port":src_port, 
                                           "server_port":dst_port}
            elif ip_pair in rdp_connection:
                if len(cookie) == 7:
                    rdp_connection[ip_pair]["status_connected"] = True
                    rdp_connection[ip_pair]["cookie_random"].add(cookie)
                    rdp_connection[ip_pair]["ttl_cookie"] = 200
                    rdp_connection[ip_pair]["client_port"] = src_port
                else:
                    rdp_connection[ip_pair]["status_connected"] = True
                    rdp_connection[ip_pair]["ttl_cookie"] = 200
                    rdp_connection[ip_pair]["client_port"] = src_port

        # negotiate respone
        elif 'neg_type' in packet.rdp.field_names and str(packet.rdp.neg_type) == '0x02':
            src_ip, dst_ip, src_port, dst_port, date_time_packet = get_info_packet(packet)
            ip_pair = "{} -> {}".format(dst_ip, src_ip)
            if ip_pair not in rdp_connection:
                rdp_connection[ip_pair] = {"status_connected":True, 
                                           "ms_t120":False, 
                                           "cookie_random":set(),
                                           "ttl_cookie":0,
                                           "tcp_windows_full":0, 
                                           "start_time":date_time_packet,
                                           "client_port":dst_port, 
                                           "server_port":src_port}
            else:
                rdp_connection[ip_pair]["status_connected"] = True
                rdp_connection[ip_pair]["client_port"] = dst_port
        # ClientData
        elif 'name' in packet.rdp.field_names:
            src_ip, dst_ip, src_port, dst_port, date_time_packet = get_info_packet(packet)
            ip_pair = "{} -> {}".format(src_ip, dst_ip)
            channel_names = str(packet.rdp.name.all_fields)
            boolean = True if 'MS_T120' in channel_names.upper() or 'MS_XXX' in channel_names.upper() else False
            if ip_pair in rdp_connection:
                rdp_connection[ip_pair]["status_connected"] = True
                rdp_connection[ip_pair]["ms_t120"] = boolean
                rdp_connection[ip_pair]["client_port"] = src_port
            else:
                rdp_connection[ip_pair] = {"status_connected":True,
                                           "ms_t120":boolean,
                                           "cookie_random":set(),
                                           "ttl_cookie":0,
                                           "tcp_windows_full":0,
                                           "start_time":date_time_packet,
                                           "client_port":src_port,
                                           "server_port":dst_port}
    # TCP packet
    elif 'tcp' in packet:
        src_ip, dst_ip, src_port, dst_port, date_time_packet = get_info_packet(packet)
        ip_pair = "{} -> {}"

        if 'analysis_window_full' in packet.tcp.field_names:
            if ip_pair.format(src_ip, dst_ip) in rdp_connection:
                ip_pair = ip_pair.format(src_ip, dst_ip)
                rdp_connection[ip_pair]["status_connected"] = True
                rdp_connection[ip_pair]["tcp_windows_full"] += 1
                rdp_connection[ip_pair]["client_port"] = src_port
            elif ip_pair.format(dst_ip, src_ip) in rdp_connection:
                ip_pair = ip_pair.format(dst_ip, src_ip)
                rdp_connection[ip_pair]["status_connected"] = True
                rdp_connection[ip_pair]["client_port"] = dst_port
        elif 'flags_fin' in packet.tcp.field_names or 'flags_reset' in packet.tcp.field_names:
            if int(packet.tcp.flags_fin) == 1 or int(packet.tcp.flags_reset) == 1:
                if ip_pair.format(src_ip, dst_ip) in rdp_connection:
                    ip_pair = ip_pair.format(src_ip, dst_ip)
                    rdp_connection[ip_pair]["status_connected"] = False
                elif ip_pair.format(dst_ip, src_ip) in rdp_connection:
                    ip_pair = ip_pair.format(dst_ip, src_ip)
                    rdp_connection[ip_pair]["status_connected"] = False
        
        if ip_pair.format(src_ip, dst_ip) in rdp_connection:
            ip_pair = ip_pair.format(src_ip, dst_ip)
            clear_cookie(ip_pair)
        elif ip_pair.format(dst_ip, src_ip) in rdp_connection:
            ip_pair = ip_pair.format(dst_ip, src_ip)
            clear_cookie(ip_pair)

def clear_cookie(ip_pair):
    global rdp_connection
    if rdp_connection[ip_pair]["ttl_cookie"] > 0:
        rdp_connection[ip_pair]["ttl_cookie"] -= 1
        if rdp_connection[ip_pair]["ttl_cookie"] == 0:
            rdp_connection[ip_pair]["cookie_random"].clear()
                
def detect_BlueKeep(save_log):
    global rdp_connection, ttl_rdp_countdown
    thread1 = threading.Thread(target=count_down, args=(int(5*60), 'ttl_rdp'))# 5 minutes
    thread1.start()
    if save_log:
        with open(log_file_name, "a") as f:
            f.write("Date: " + str(datetime.datetime.now()) + "\n")

    while True:
        time.sleep(0.5)
        ip_pairs = list(rdp_connection.keys()).copy()
        for ip_pair in ip_pairs:
            if rdp_connection[ip_pair]["status_connected"] == True:
                contents = []
                if rdp_connection[ip_pair]["ms_t120"] == True:
                    contents.append('request contains channel MS_T120')
                    rdp_connection[ip_pair]["ms_t120"] = False
                if len(rdp_connection[ip_pair]["cookie_random"]) >= 3:
                    contents.append('request contains cookies random')
                    rdp_connection[ip_pair]["cookie_random"].clear()
                if rdp_connection[ip_pair]["tcp_windows_full"] > 0:
                    contents.append('server buffer is full')
                    rdp_connection[ip_pair]["tcp_windows_full"] = 0
                if len(contents) > 0:
                    alert_message = 'Warning! {}:{} -> {}:{} :: Potential CVE-2019-0708 BlueKeep Exploit - {} - start time:{}'
                    ip_attacker = ip_pair[:ip_pair.index("->")-1]
                    ip_server = ip_pair[ip_pair.index(">")+2:]
                    port_attacker = rdp_connection[ip_pair]["client_port"]
                    port_server = rdp_connection[ip_pair]["server_port"]
                    _time = rdp_connection[ip_pair]["start_time"]
                    for content in contents:
                        alert_message = alert_message.format(ip_attacker, port_attacker, ip_server, port_server, content, _time)
                        print(alert_message)
                        if save_log:
                            with open(log_file_name, "a") as f:
                                f.write(alert_message + "\n")
        
        if ttl_rdp_countdown == False:
            for ip_pair in ip_pairs:
                if rdp_connection[ip_pair]["status_connected"] == False:
                    del rdp_connection[ip_pair]["status_connected"]
            ttl_rdp_countdown = True    

def monitor():
    print('*start monitoring')
    thread2 = threading.Thread(target=detect_BlueKeep, args=(True, ))
    thread2.start()
    packets = pyshark.LiveCapture(interface=iface_name, bpf_filter=bpf_filter_string, display_filter=display_filter_string)
    for packet in packets.sniff_continuously():
        matched_signature_BlueKeep(packet)

def stop_program(time_h):
    print('Press "q" to stop monitor and quit.')
    process3 = multiprocessing.Process(target=count_down, args=(int(time_h)*60*60, 'program',))
    process3.start()
    while True:
        if keyboard.is_pressed('q'):
            process3.kill()
            return True
        if not process3.is_alive():
            return True

if __name__ == '__main__':
    p1 = multiprocessing.Process(target=stop_program, args=(1,))
    p2 = multiprocessing.Process(target=monitor)
    
    p2.start()
    p1.start()

    p1.join()
    
    if not p1.is_alive():
        p2.terminate()
        print('bye.')