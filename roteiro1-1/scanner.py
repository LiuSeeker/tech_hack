import socket
from scapy.all import *
import netifaces as ni
from datetime import datetime
import sys

def parser(text):
    ### Parser do input de range de ips / portas
    pos = 0
    ret = []
    f_range = False

    if len(text) == 1:
        if text[pos].isdigit():
            ret.append(text)
            return ret

    while pos < len(text):
        if text[pos].isdigit():
            i = pos
            pos += 1
            if pos < len(text):
                while text[pos].isdigit():
                    pos += 1
                    if pos == len(text):
                        break
            if f_range:
                for e in range(int(ret[-1])+1, int(text[i:pos]), 1):
                    ret.append(str(e))
                f_range = False
            ret.append(text[i:pos])
        elif text[pos] == "," or text[pos] == " ":
            pos += 1
        elif text[pos] == "-":
            f_range = True
            pos += 1
        else:
            raise SyntaxError("Caractere nao permitido '{}'".format(text[pos]))
    
    return ret

def udp_scan(dst_ip,dst_port,dst_timeout,serv_n):
    # https://resources.infosecinstitute.com/port-scanning-using-scapy/#gref
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout, verbose=0)
    if (udp_scan_resp is None):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout, verbose=0))
        for item in retrans:
            #print(item)
            if (item is None):
                #udp_scan(dst_ip,dst_port,dst_timeout,serv_n)
                print("Port {}{} : Open|Filtered".format(dst_port, serv_n))
            elif (item.haslayer(UDP)):
                print("Port {}{} : Open".format(dst_port, serv_n))
            elif(item.haslayer(ICMP)):
                if(int(item.getlayer(ICMP).type)==3 and int(item.getlayer(ICMP).code)==3):
                    print("Port {}{} : Closed".format(dst_port, serv_n))
                elif(int(item.getlayer(ICMP).type)==3 and int(item.getlayer(ICMP).code) in [1,2,9,10,13]):
                    print("Port {}{} : Filtered".format(dst_port, serv_n))
            else:
                print("dffsdfsfd")
    else:
        print(udp_scan_resp)

def main():
    opt = None
    if len(sys.argv) > 1:
        opt = sys.argv[1]

    ### Identifica as interfaces de rede e seus ips
    available_interfaces = []
    for interface in ni.interfaces():
        if 2 in ni.ifaddresses(interface).keys():
            ip_address = ni.ifaddresses(interface)[2][0]["addr"]
            i = len(ip_address)
            while i > 0:
                if ip_address[i-1] == ".":
                    break
                ip_address = ip_address[:-1]
                i -= 1
            available_interfaces.append(ip_address+'0')

    if not available_interfaces:
        print("Nenhuma interface de rede disponivel")
        return 0

    ### Selecao da rede
    print("Escolha a rede: ")
    for i in range(len(available_interfaces)):
        print("({}) {}".format(i, available_interfaces[i]))
    inter_opt = input(">> ")
    while int(inter_opt) > len(available_interfaces)-1 or int(inter_opt) < 0:
        print("Opcao invalida.")
        inter_opt = input(">> ")

    remote_host_pre = available_interfaces[int(inter_opt)]

    ### Range de ips
    print("""Digite o range de ips a serem scaneados com traco (ex: 10-20)""")
    ips_opt = input(">> ")
    ips_end = parser(ips_opt)
    remote_hosts = []
    for ip_end in ips_end:
        remote_hosts.append(remote_host_pre[:-1] + ip_end)

    ### Tipo de portocolo
    print("Scan de portas TCP (1) ou UDP (2): ")
    protocol_opt = input(">> ")
    while protocol_opt not in ["1", "2"]:
        print("""Opcao invalida. Digite '1' para TCP 
            ou '2' para UDP""")
        protocol_opt = input(">> ")
    if protocol_opt == "1":
        protocol = socket.SOCK_STREAM
        protocol_n = "tcp"
    elif protocol_opt == "2":
        protocol = socket.SOCK_DGRAM
        protocol_n = "udp"

    ### Range de portas
    print("""Digite as portas a serem scaneadas separadas por
        virgulas ou espaco e com traco em caso de range (ex: 1,3,10-20,30)""")
    ports_opt = input(">> ")
    ports = parser(ports_opt)

    print("")
    for remote_host in remote_hosts:
        print("Scaneando host {}".format(remote_host))
        ti = datetime.now() #Inicio do tempo

        for port in ports:
            sock = socket.socket(socket.AF_INET, protocol)
            try:
                serv_n = socket.getservbyport(int(port), protocol_n)
                serv_n = " ({})".format(serv_n)
            except OSError:
                serv_n = ""
            
            # TCP
            # https://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python/
            if protocol_n == "tcp":
                result = sock.connect_ex((remote_host, int(port)))
                if result == 0:
                    print("Port {}{} : Open".format(port, serv_n))
                elif opt != "-c" and result == 10061:
                    print("Port {}{} : Closed".format(port, serv_n))
                elif result == 10060:
                    print("Nao foi possivel conectar ao host")
                    break
                else:
                    print("result n tratado {}".format(result))
            
            # UDP
            elif protocol_n == "udp":
                udp_scan(remote_host,int(port),10,serv_n)

            sock.close()

        tf = datetime.now() #Fim do tempo
        print("Tempo scan: {}".format(tf-ti))
        print("")


if __name__ == "__main__":
    main()