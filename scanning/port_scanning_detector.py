#!/usr/bin/env python
from datetime import datetime
import socket, sys
import time
from struct import *
from collections import OrderedDict
from config.config import DBConnectionConf
from database.detections_repo import DetectionRepo, debug
from model.detection import Detection, ModuleName 
fileName = "test.txt"

def writeDetection(str):
    with open(fileName, 'a') as file:
        file.write(str)
        file.write('\n')

class PortScanningDetector:
    def __init__(self, dbConfig: DBConnectionConf):
        try:
            self.socket = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))
        except socket.error as msg:
            #TODO lepsza obsługa błędów 
            debug('[*]Socket can\'t be created! Error Code : ' + str(msg[0]) + ' Error Message ' + msg[1])
            sys.exit()
        except AttributeError:
            sys.exit()
        self.dbConfig = dbConfig
        self.halfscandb = {}
        
    def parse_flags(self, dec):
        final = []
        flags = OrderedDict([("128","CWR"),("64","ECE"),("32","URG"),("16","ACK"),("8","PSH"),("4","RST"),("2","SYN"),("1","FIN")])
        for i in flags.keys():
            if(dec>=int(i)):
                dec = dec-int(i)
                final.append(flags[i])
        return final

    def scancheck(self, sip, dip, sport, dport, seqnum, acknum, flags):
        revthreeway = dip+":"+str(dport)+"->"+sip+":"+str(sport)
        dbdata = sip+"->"+dip
        reverse = dip+"->"+sip
        if("SYN" in flags and seqnum>0 and acknum==0 and len(flags)==1):
            self.halfscandb[dbdata+"_"+str(seqnum)] = dbdata+"_SYN_ACK_"+str(seqnum)+"_"+str(acknum)
        elif("RST" in flags and "ACK" in flags and len(flags)==2):
            tmp = reverse+"_"+str(acknum-1)
            if tmp in self.halfscandb:
                del self.halfscandb[reverse+"_"+str(acknum-1)]
                detection = Detection(
                    detection_time=datetime.now(),
                    attacker_ip_address=dip,
                    module_name=ModuleName.PORTSCANNING_MODULE,
                    note="Attacked port: {}".format(str(dport))
                )
                self.repo.add(detection)

    def run(self):
        self.repo = DetectionRepo(self.dbConfig)
        while True:
            try:
                # https://en.wikipedia.org/wiki/File:Ethernet_Type_II_Frame_format.svg
                # wielkość buffera
                packet = self.socket.recv(65565)
                eth_length = 14
                eth_header = packet[:eth_length]
                # 6s - 6 bytes
                # H - unsigned short (2 bytes)
                eth = unpack('! 6s 6s H' , eth_header)
                # ether_type in network byte order
                (dest_mac, source_mac, ether_type) = eth
            except:
                pass

            #ipV4 https://en.wikipedia.org/wiki/EtherType
            if ether_type == 2048 :
                ip_header_packed = packet[eth_length:20+eth_length]
                #https://nmap.org/book/tcpip-ref.html
                ip_header = unpack('!BBHHHBBH4s4s' , ip_header_packed)
        
                #version and IHL (header length) are on one byte
                version_and_ihl = ip_header[0]
                version = version_and_ihl >> 4
                ihl = version_and_ihl & 0xF
        
                iph_length = ihl * 4
                protocol = ip_header[6]
                s_addr = socket.inet_ntoa(ip_header[8])
                d_addr = socket.inet_ntoa(ip_header[9])
            
            
                #TCP protocol
                if protocol == 6 :
                    t = iph_length + eth_length
                    tcp_header_packed = packet[t:t+20]
                    
                    # https://www.gatevidyalay.com/wp-content/uploads/2018/09/TCP-Header-Format.png
                    tcp_header = unpack('!HHLLBBHHH' , tcp_header_packed)

                    source_port = tcp_header[0]
                    dest_port = tcp_header[1]
                    seq_numb = tcp_header[2]
                    ack_numb = tcp_header[3]
                    tcp_flags = self.parse_flags(tcp_header[5])

                    self.scancheck(s_addr,d_addr,source_port,dest_port,seq_numb,ack_numb,tcp_flags)