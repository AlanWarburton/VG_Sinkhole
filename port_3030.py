#!/usr/bin/env python

import os
import re
import csv
import time
import json
import socket
import binascii
import threading
import subprocess
from multiprocessing import Process, Lock

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


class MultiThreading(object):
    def __init__(self, ip, port):
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
            threading.Thread(target = self.newClient,args = (client, ip)).start()

    def logger(self, raddr, rport):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        timestamp = '"%s"' % timestamp
        columns = "timestamp", "ip", "port", "cc_ip", "cc_port", "infection"
        localPort = self.port
        localAddr = PUBLIC_IP
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
                        line = ','.join(str(x) for x in (timestamp, raddr, rport, localAddr, localPort, FAMILY))
                        log.write(line + "\n")
                        log.close()
                        self.prohibitNewConn(raddr, mutex)
            except:
                mutex.release()

    def stringToHex(self, unicode):
        bytes = bytearray(unicode)
        hex = binascii.hexlify(bytes)
        return hex

    def validateBuffer(self, recv_buffer):
        received = self.stringToHex(recv_buffer)
        if received.startswith(SIGNATURE):
            return True
        else:
            return False

    def prohibitNewConn(self, ip_addr, mutex):
        try:
            p = subprocess.Popen(["sudo", "iptables", "-w", "-A", "INPUT", "-s", ip_addr, "-j", "DROP"], stdout=subprocess.PIPE)
            p.communicate()
            mutex.release()
        except:
            mutex.release()

    def newClient(self, client, ip):
        while True:
            try:
                msg = client.recv(BUFFER)
                if self.validateBuffer(msg):
                    client_ip = ip[0]
                    client_port = ip[1]
                    self.logger(client_ip, client_port)
                    client.close()
                else:
                    self.prohibitNewConn(client_ip)
                    client.close()
                    return False
            except:
                client.close()
                return False

try:
    url = "https://ipinfo.io/json"
    response = urllib2.urlopen(url)
    data = json.load(response)
    PUBLIC_IP = data['ip']
    MultiThreading(TCP_IP, TCP_PORT).listen()
except KeyboardInterrupt:
    print ("\nShutting down server on user interrupt... Wait for all threads to finalize")
    raise SystemExit()
except Exception as e:
    print ("\n[!] Unexpected error:\n")
    print (e)
    raise SystemExit()
