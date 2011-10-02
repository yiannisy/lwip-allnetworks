#!/usr/bin/python

import pcap
import dpkt
import logging
import time
import threading
import SocketServer
import math
import shlex, subprocess
import socket
from optparse import OptionParser


RATE_LIM_IFACE='eth0'
DEFAULT_IFACE='eth0'
DEFAULT_UDP_FEEDBACK_PORT=9091
PORT=8081
PKT_SIZE=1024

unacked = {}
rtts = []
times = []
rcvd_pkts=[]
rtt_avg = 0
weights = [1,1,1,1,0.8,0.6,0.4,0.2]
s_intervals = []

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

def setup_local_qdisc():
    cmd = "tc qdisc add dev %s root handle 1: htb default 14" % RATE_LIM_IFACE
    args = shlex.split(cmd)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out,err = p.communicate()
    logging.warn("%s : %s" % (out,err))

    cmd = "tc class add dev %s parent 1:15 classid 1:14 htb rate 1024kbit ceil 1024kbit" % RATE_LIM_IFACE
    args = shlex.split(cmd)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out,err = p.communicate()
    logging.warn("%s : %s" % (out,err))

def setup_rate(rate):
    cmd = "tc class change dev %s parent 1:15 classid 1:14 htb rate %dkbit ceil %dkbit" % (RATE_LIM_IFACE, rate, rate)
    args = shlex.split(cmd)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out,err = p.communicate()

    logging.warn("%s : %s" % (out,err))

def _set_congestion(value):
    logging.info("Setting Congestion to %d" % value)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(str(value), ('localhost',9092))

def send_ploss_report(p_loss):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(p_loss, ("171.67.75.16", 9091))

# maintain history of the last 8 loss events
def add_loss_interval(loss_interval_sample):
    global s_intervals
    s_intervals.insert(0, loss_interval_sample)
    if len(s_intervals) > 8:
        s_intervals = s_intervals[0:7]

# calculates the average loss p, used for throughput calculation.
def get_avg_loss_prop():
    global s_intervals
    _avg_loss = float(sum([i*j for i,j in zip(weights,s_intervals)]))/float(sum(weights[0:len(s_intervals)]))
    return 1.0/_avg_loss
    


# check if the sample makes sense.
# If it does, returen the running average.
def get_avg_rtt(avg, rtt_sample):
    if (rtt_sample < 0 or rtt_sample > 3):
        logging.warn("non-sense RTT : %f" % rtt_sample)
        return avg
    if avg > 0:
        return (0.9*avg + 0.1*rtt_sample)
    else:
        return rtt_sample
    
class IfListener(threading.Thread):
    def __init__(self, iface, is_receiver):
        threading.Thread.__init__(self)
        self.s_a = 0
        self.rtt_avg = 0
        self.p = pcap.pcap(iface)
        self.p.setfilter("port %d" % PORT)
        self.is_receiver = is_receiver
#        self.setup_recv_raw_socket(iface)
        
    def run(self):
        dispatched = 1
        try:
            while(dispatched == 1):
                if (self.is_receiver):
                    logging.info("Running on the receiver side")
                    dispatched = self.p.dispatch(0, self.receiver_handle_packet)
                    self.p.loop(self.receiver_handle_packet)
                else:
                    logging.info("Running on the sender side")
                    dispatched = self.p.dispatch(0, self.sender_handle_packet)
                    self.p.loop(self.sender_handle_packet)
        except KeyboardInterrupt:
            logging.info("Quitting Listener Thread...")
            
    def sender_handle_packet(self, timestamp, pkt):
        global rtt_avg
        tcp_hdr = dpkt.ethernet.Ethernet(pkt).data.data
        if tcp_hdr.flags & dpkt.tcp.TH_ACK and tcp_hdr.dport == PORT:
            try:
                _sent = unacked[int(tcp_hdr.ack)]
                times.append(timestamp)
                rtt = timestamp - _sent
                rtts.append(rtt)
                self.rtt_avg = get_avg_rtt(self.rtt_avg, rtt)
                # logging.info("Current RTT average : %f" % self.rtt_avg)
                rtt_avg = self.rtt_avg
                # print "Received ack %d at %f" % (tcp_hdr.ack, timestamp)
            except KeyError:
                pass
                # print "Could not find seq %d" % (int(tcp_hdr.ack))
        else:
            # print "Sending packet %d at %d" % (tcp_hdr.seq, timestamp)
            unacked[int(tcp_hdr.seq)] = timestamp

    def receiver_handle_packet(self, timestamp, pkt):
        tcp_hdr = dpkt.ethernet.Ethernet(pkt).data.data
        if tcp_hdr.sport == PORT and (tcp_hdr.flags & dpkt.tcp.TH_SYN == 0):
            if len(rcvd_pkts) > 0:
                if(tcp_hdr.seq < rcvd_pkts[-1][0]):
                    logging.warn("This seems like a rtxmit - ignoring...")
                    return
                _gap = tcp_hdr.seq - rcvd_pkts[-1][1]
                if (_gap > 1):
                    _lost = rcvd_pkts[-1][1]
                    if self.s_a != 0:
                        interval = (_lost - self.s_a)/1024
                        add_loss_interval(interval)
                        logging.info("Lost packet detected - current p_loss estimate:%f" % get_avg_loss_prop()) 
                        send_ploss_report(get_avg_loss_prop())
                    self.s_a = rcvd_pkts[-1][1]
                    # logging.info("Missing %d bytes (%d packets) in the between" % (_gap, _gap/PKT_SIZE))
            rcvd_pkts.append((tcp_hdr.seq, tcp_hdr.seq + len(tcp_hdr.data)))
            # print "Received packet of size %d" % len(tcp_hdr.data)
            
            
class FeedbackHandler(SocketServer.BaseRequestHandler):
    dccp_active = False

    @staticmethod
    def enable_dccp():
        dccp_active = True

    @staticmethod
    def disable_dccp():
        dccp_active = False

    def handle(self):
        global rtt_avg
        data = self.request[0].strip()
        throughput = (math.sqrt(1.5)*1024*8)/(math.sqrt(float(data))*rtt_avg*1000)
        logging.info("Received p-loss report %s (RTT : %f)" % (data, rtt_avg))
        logging.info("Estimated throughput is %f" % throughput)
        if(self.dccp_active):
            logging.info("Setting Rate at Switch")
            setup_rate(int(throughput))
        else:
            logging.info("Rate not sent since dccp is not active")
                     
class FeedbackServer(SocketServer.ThreadingUDPServer):
    def __init__(self, host='localhost', port=None, handler=FeedbackHandler):
        if port is None:
            port = DEFAULT_UDP_FEEDBACK_PORT
        SocketServer.ThreadingUDPServer.__init__(self, (host, port), handler)
                                                                                 
if __name__ == "__main__":
    usage = "usage: %prog [options] arg"
    description = "TCP/DCCP congestion control"
    parser = OptionParser(usage)
    parser.description = description
    parser.add_option("-r","--receiver",dest="is_receiver",action="store_true", default=False,
                      help="Script running on the receiver side (calculate p_loss instead of RTT")

    (options, args) = parser.parse_args()

    setup_local_qdisc()
    
    listener = IfListener(DEFAULT_IFACE, options.is_receiver)
    listener.start()

    if(not options.is_receiver): 
        feedback_rcver = FeedbackServer(host='0.0.0.0')
        thr_feedback = threading.Thread(target=feedback_rcver.serve_forever)
        thr_feedback.daemon = True
        logging.info("Starting Feedback Server Thread")
        thr_feedback.start()

        time.sleep(300)
        logging.info("Disable congestion and enable DCCP")
        _set_congestion(0)
        FeedbackHandler.enable_dccp()
        time.sleep(300)
        FeedbackHandler.disable_dccp()
        logging.info("Setting User Specified Rate")
        setup_rate(256)

#        while(True):
#            time.sleep(10)
#            _set_congestion(1)
#            time.sleep(10)
#            _set_congestion(0)
