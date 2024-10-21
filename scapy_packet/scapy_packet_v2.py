# -*- coding: utf-8 -*-
"""scapy_packet.ipynb

Automatically generated by Colab.

Original file is located at
    https://colab.research.google.com/drive/1i8qtCnXUf4lExmlRg6V4MzLDAMT8a7b1
"""

import scapy.layers.l2
from scapy.all import *
import time
import threading

def password_check():
  result = True

  # 비밀번호검사 or 인증 후 true 반환

  return result

def alert(mac):
  print("\n" + mac + "사용자가 접근 시도\n")
  # print 이용했으나 현재 이용자에게 직접적인 경고로 취급

user_mac_list = []
user_connect = False

count = 1
protocols = {1:'icmp', 6:'tcp', 17:'udp'}
protocol_type = input("Protocol: ") # icmp, udp, tcp
sniffing_time = input("Time: ")

def sniffing():
    print("Sniffing Start")
    pcap_file = sniff(prn=showPacket, timeout=int(sniffing_time), filter=str(protocol_type), iface='wlan0')
    print("Finish Capture Packet")
    if count == 1:
            print("No Packet")
            sys.exit()
    else:
        print("Total Packet: %s" %(count-1))
        file_name = input("Enter File Name: ")
        wrpcap(str(file_name), pcap_file)


def showPacket(packet):
    global count
    # IP
    if IP in packet:  # IP 계층이 있는지 확인
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        length = packet[IP].len
        
        if proto in protocols:
            # ICMP
            if proto == 1:
                message_type = packet[ICMP].type
                code = packet[ICMP].code

                print("packet number: %s protocol: %s" %(count, protocols[proto].upper()))
                print("src: %s -> dst: %s TTL: %s" %(src_ip, dst_ip, ttl))
                print("type: %s code: %s" %(message_type, code))
                print("\n")

            # TCP
            if proto == 6:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                seq = packet[TCP].dport
                ack = packet[TCP].ack
                flag = packet[TCP].flags

                print("packet number: %s protocol: %s" %(count, protocols[proto].upper()))
                print("src: %s -> dst: %s" %(src_ip, dst_ip))
                print("TTL: %s Length: %s" %(ttl, length))
                print("sport: %s dport: %s" %(sport, dport))
                print("seq: %s ack: %s flag: %s" %(seq, ack, flag))
                print("\n")

            # UDP
            if proto == 17:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                udp_length = packet[UDP].len
                print("packet number: %s protocol: %s" %(count, protocols[proto].upper()))
                print("src: %s -> dst: %s TTL: %s" %(src_ip, dst_ip, ttl))
                print("sport: %s dport: %s Packet Length: %s" %(sport, dport, udp_length))
                print("\n")
            count += 1

def check_mac():

  net ='192.168.35.1/24' # ip 대역 설정

  ans, noans = scapy.layers.l2.arping(net, timeout=1, verbose=True)

  while True:
      for sent, received in ans.res:
          mac = received.hwsrc

          if mac in user_mac_list:
            user_connect = True
          else:
            if password_check():
              user_connect = True
              user_mac_list.append(mac)
            else:
              alert(mac)


      time.sleep(0.2)

thread_1 = threading.Thread(target = check_mac)
thread_2 = threading.Thread(target = sniffing)

thread_1.start()
thread_2.start()

time.sleep(10)
print(user_mac_list)