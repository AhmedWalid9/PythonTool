import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import subprocess 
import socket
from socket import *
import time
import os
from scapy.all import *
import iptc
from bs4 import BeautifulSoup
import requests
import re
from bs4 import Comment

def valid(lst, inpE):
    inp = -1
    while inp not in range(1, inpE+1):       
        for i in lst:
            print(i)
        inp = int(input("Input: "))
        os.system("clear")
    return inp

lst = ["choose your programm : ", "1: Log parser", "2: Directory Monitor ", "3: Scanner", "4: Detector", "5: Scraper"]
choice =valid(lst, 5)

if choice == 1 :
    try:
        Logs_File = open('logs.txt','r')
        Lines = Logs_File.readlines()
        logs = []
        for i in Lines:
            logs.append(i.split())
        for Element in logs:
            print("(IP "+ Element[0] +  ") (Access method: " + Element[5][1:] + ") (URI: " + Element[6][1:-1]+") (User agent: " + (' '.join(Element[11:-1]))[1:-1] +")")
    except:
        print("File Corrupted or not found")
        exit(1)

################################################################################
if choice == 2 :
    print("Create a directory named monitored_path to be monitored\n")
    print("Choose the output method")
    opt = valid(["1. File", "2. Screen"], 2)
    if opt == 1:
        logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename="savedlogs.txt")
    else:
        logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    event_handler = LoggingEventHandler()
    observer = Observer()
    observer.schedule(event_handler, 'monitored_path' ,recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
#################################################################################
if choice == 3 :
    startTime = time.time()
    up = []
    for ping in range(130,133): 
        address = "127.0.0." + str(ping) 
        res = subprocess.call(['ping', '-c', '2', address]) 
        if res == 0: 
            print( "ping to", address, "OK") 
            up.append(address)
        elif res == 2: 
            print("no response from", address) 
        else: 
            print("ping to", address, "failed!") 

    print(up)

    if __name__ == '__main__':
        
        IP_Port = {}
        for element in up:
            IP_Port[element] = []
            t_IP = gethostbyname(element)
            print ('Starting scan on host: ', t_IP)
            
            for i in range(50, 500):
                s = socket.socket(AF_INET, SOCK_STREAM)
                conn = s.connect_ex((t_IP, i))
                if(conn == 0) :
                    print ('Port %d: OPEN' % (i,))
                    IP_Port[element].append(i)
                s.close()
        for ip in IP_Port:
            ports = IP_Port[ip]
            ports = [str(i) for i in ports]
            ports = ','.join(ports)
            CMD = "nmap -sV -p " + ports + " " + ip
            nmapscan = os.popen(CMD).read()
            print(nmapscan)

    print('Time taken:', time.time() - startTime)
###############################################################################
if choice == 4 :
    def Open(port):
        os.system("nc -nvlp " + str(port) + " &")

    def UOP():
        global myIP
        host = socket.gethostbyname(myIP)
        openPorts = []
        for port in range(1, 20000):
            if port not in wellknown and port < 20000:
                scannerTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.1)
                status = scannerTCP.connect_ex((host, port))
                if not status:
                    openPorts.append(port) 
        for p in openPorts:
            os.system("nc -nvlp " + str(p) + " &")
        return openPorts

    def blockIP(ip):
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        rule = iptc.Rule()
        rule.in_interface = "eth0"
        target = iptc.Target(rule, "DROP")
        rule.target = target
        rule.src = ip  
        chain.insert_rule(rule)

        os.system("iptables -A OUTPUT -d " + "" + ip + " " + "-j DROP") 

    def print_summary(pkt):
        global myIP
        global unKnown
        tcp_sport = ""

        if 'TCP' in pkt:
            tcp_sport=pkt['TCP'].sport

        if (pkt['IP'].src == myIP)  and tcp_sport in unKnown:
            blockIP(pkt['IP'].dst)
            Open(tcp_sport)
            print("Attack detected!")
            print("Blocking " + pkt['IP'].dst + " ...\nBlocked!\n")


    def Monitor():
        sniff(filter="ip",prn=print_summary)
        sniff(filter="ip and host " + myIP, prn=print_summary)

    wellknown = [1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53,
    69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143,
    150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    unKnown = UOP()

    if __name__ == "__main__":
        if(len(unKnown)):
            print("My ip is " + myIP + "....")
            Monitor()
        else:
            print("No ports were detected")
##################################################################################
if choice == 5 :
    domain = raw_input("Enter Domain name like cisco.com : ")
    DOM ="http://www."+domain
    resp = requests.get(DOM)
    src = resp.content
    soup = BeautifulSoup(src , "lxml")
    urls = []
    links = soup.find_all('a')
    complete = [a.get('href') for a in soup.find_all('a', href=True)]
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    tags = [tag.name for tag in soup.find_all()]
    taags = set(tags)
    for link in links: 
        if domain in link.attrs['href']:
            s = link.attrs['href'][:link.attrs['href'].index(domain)]
            obj=re.compile(r'http://|https://(\w.+).')
            url = obj.findall(s)
            lsurl = list(url)
            urls.append(lsurl)
    print("\n\n\nURLS ===========================================>>")
    for i in complete:
        print(i)
    print("\n\n\nTAGS ===========================================>>")
    for j in taags:
        print(j)
    print("\n\n\nSUBDOMAINS ===========================================>>")
    for k in urls:
        print(k)
    print("\n\n\nCOMMENTS ===========================================>>")
    for l in comments:
        print(l)
