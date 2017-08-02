#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automatic Security Tool to:
# 1. Detect machines   (python-nmap)
# 2. Detect Open Ports (python-nmap)
# 3. BANNER Grabbing   (scapy,socket)

import os
import socket
import sys
import argparse
import nmap
import os
import MySQLdb
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dbhost = os.environ['mydbhost']
dbpasswd = os.environ['mydbpasswd']
dbname = os.environ['mydname']
dbuser = os.environ['mydbuser']

conf.verb = 0 #DISABLE VERBOSE SCAPY SR1

def sniff_sniff():
    print('''\t\t\t
                             @
                            @@@
                           @@@@@               camisade.py
                          @@@@@@@              Automatic Discovery and Banner Grabbing Tool
                         @@@@@@@@@
                        @@@@@@@@@@@
                       @@@@@@@@@@@@@           Version: 1.0
                       @@@@@@@@@@@@@           Author: @tomride
                       @@@@@@@@@@@@@
                       @@@@@@@@@@@@@
                        @@@@@@@@@@@
                         @@@@@@@@@
                            @@
                           @@@@
                        @@@@@@@@@@
        ''')


def main():

    parser = argparse.ArgumentParser("camisade.py")
    parser.add_argument("-t","--target", dest="target", type=str, help="Range to Analyze", metavar="IP/URL")
    parser.add_argument("-d","--view", dest="view", type=str, help="View Live machines", metavar="IP/URL")

    args = parser.parse_args()

    if args.target:
        sniff_sniff()
        scan(args.target)
    elif args.view:
        sniff_sniff()
        detect(args.view)
    else:
        parser.print_help()


def scan(target):
    obj =  nmap.PortScanner()
    obj.scan(hosts=target,arguments='-sT')

    for host in obj.all_hosts():
        print '\nHost: ' , host
        print "----------------------------"
        for proto in obj[host].all_protocols():
            lport = obj[host][proto].keys()
            lport.sort()
            for port in lport:
                ban = bannerread(host,port)
                print ('Open Port: %s  \t %s' % (port, ban))



def bannerread(host,port):
    try:
        if port==80 or port==8443 or port==2089 or port==10000:
            con = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            con.connect((host,port))
            con.send("GET / HTTP/1.1\r\n\r\n\r\n")
            data = (con.recv(200))
            dbcon(host,port,data)
            return(data)
        elif port==53:
            pkt = IP(dst=host)/UDP(dport=port,sport=RandShort())/DNS(aa=0L, qr=0L, qd=DNSQR(qclass=3, qtype=16, qname='version.bind.'))
            x = sr1(pkt)
            ban = x[DNS].summary()
            dbcon(host,port,data)
            return(ban)
        else:
            conexion = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            conexion.settimeout(1.0) #Timeout - socket non-blocking
            conexion.connect((host,port))
            banner = conexion.recv(1024)
            dbcon(host,port,banner)
            return(banner)
    except:
        return("No Banner")


"""To Detect Machines"""

def detect(target):
    list1=[]
    scn = nmap.PortScanner()
    scn.scan(hosts=target,arguments='-sP')
    if not scn.all_hosts():
        print("Down")
    for host in scn.all_hosts():
        print 'Live: ', host

    return(list1)

"""To Insert Banners"""

def dbcon(host,port,ban):
        try:
            dbconn = MySQLdb.connect (
            host = dbhost,
            user = dbuser,
            passwd = dbpasswd,
            db = dbname)

            cur = dbconn.cursor()
            sql = 'INSERT INTO Banners VALUES("%s","%s","%s")' % (host,port,ban)
            cur.execute(sql)
            dbconn.commit()
        except:
            print "Duplicate Entry or Database Connection Error "
            return()

if __name__ == "__main__":
    main()
