import os
from scapy.all import *

# get rules from the user
'''def get_rules():
    rules_list = list()
    rules_list = ["1-) PORT ARALIGI EN ONEMLI 100 PORT OLSUN",
                "2-) "]
    print("Select the rules:")
    return rules_list '''

#p = sniff(filter='tcp', iface='wlp4s0' , timeout=10, count=10 )
# show packet details
def packet_callback(packet):

    print(packet.show())


# start the wifi interface sniffer
def start_sniffer():
    p = sniff(filter='tcp' , iface='wlp4s0', timeout=10, count=500 )
    #wrpcap('packets.pcap', p)
    # packet = sniff(filter='icmp', iface='wlp4s0', prn=packet_callback, count=0)
    #p = sniff(filter='tcp or udp' , iface='enp3s0', prn=packet_callback, count=10)

     #print(p.summary())
    print(type(p.summary()))
    #print(type(wrpcap.summary()))

if __name__ == "__main__":
    print("[+] Program started.")
    #user_rules = list()
    #user_rules = get_rules()
    start_sniffer()
    #packet_callback(p)
