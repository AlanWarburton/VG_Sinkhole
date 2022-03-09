#!/usr/bin/env python

import binascii
import csv
import json
from multiprocessing import Process, Lock
import os
import re
import socket
import subprocess
import time
import threading


# Define interface to listen on. Leave blank to listen on all interfaces.
TCP_IP = ''

# Define port to listen on
TCP_PORT = 3030

# Define max parallel threads
QUEUE = 10

# Define the maximum buffer size for incomming connections (in bytes)
BUFFER = 256

# Define the path to the log file to be generated
LOGPATH = "/home/vgate/sinkholing/log.csv"

# Define the first few bytes of the stream to validate. By default, this script will
# validate if the stream STARTS with these bytes. This behaviour could be modified in
# validateBuffer() method.
SIGNATURE = "5b2d5d7c"

# Define name of the malware family to add to the output log under the property "infection"
FAMILY = "VictoryGate.A"

# Finally, the public IP address is resolved dynamically querying ipinfo.io API (below). If for
# whatever reason this is not possible, set the variable PUBLIC_IP manually. For logging purposes only.


class Helpers:  
    @staticmethod
    def stringToHex(unicode: str) -> bytes:
        bytes = bytearray(unicode)
        hex = binascii.hexlify(bytes)
        return hex

    @staticmethod
    def prohibitNewConn(ip_addr: str, mutex: threading.Lock) -> None:
        """Block an IP address on the local firewall (iptables)."""
        try:
            p = subprocess.Popen(["sudo", "iptables", "-w", "-A", "INPUT", "-s", ip_addr, "-j", "DROP"], stdout=subprocess.PIPE)
            p.communicate()
            mutex.release()
        except:
            mutex.release()

    @staticmethod
    def validateBuffer(recv_buffer: bytes) -> bool:
        """Check if the received buffer matches the malware signature."""
        received = Helpers.stringToHex(recv_buffer)
        if received.startswith(SIGNATURE):
            return True
        return False
    
    @staticmethod
    def logger(raddr: str, rport: int, lport: int) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        columns = "timestamp", "ip", "port", "cc_ip", "cc_port", "infection"
        mutex = Lock()
        if not os.path.isfile(LOGPATH):
            with open(LOGPATH, 'a+') as write_obj:
                csv_writer = csv.writer(write_obj)
                csv_writer.writerow(columns)
        with mutex:
            try:
                time.sleep(0.035)
                if os.path.isfile(LOGPATH):
                    with open(LOGPATH, "a") as log:
                        line = ','.join(str(x) for x in (timestamp, raddr, rport, PUBLIC_IP, lport, FAMILY))
                        log.write(line + "\n")
                        log.close()
                        Helpers.prohibitNewConn(raddr, mutex)
            except:
                mutex.release()
    
    
class Server:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.ip, self.port))

    def listen(self):
        self.server_socket.listen(QUEUE)
        while True:
            client, ip = self.server_socket.accept()
            client.settimeout(20)
            threading.Thread(target = self.newClient, args = (client, ip)).start()

    def newClient(self, client, ip: tuple):
        while True:
            try:
                msg = client.recv(BUFFER)
                if Helpers.validateBuffer(msg):
                    client_ip, client_port = ip
                    Helpers.logger(client_ip, client_port, self.port)
                else:
                    Helpers.prohibitNewConn(client_ip)
                    return False
            except:
                return False
            
            finally:
                client.close()


if __name__ == "__main__":
    try:
        url = "https://ipinfo.io/json"
        response = urllib2.urlopen(url)
        PUBLIC_IP = json.load(response).get("ip")
        Server(TCP_IP, TCP_PORT).listen()
        
    except KeyboardInterrupt:
        print ("\nShutting down server on user interrupt... Wait for all threads to finalize")
        raise SystemExit()
        
    except Exception as e:
        print ("\n[!] Unexpected error:\n")
        print (e)
        raise SystemExit()
