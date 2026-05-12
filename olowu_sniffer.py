from scapy.all import sniff
from datetime import datetime
packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1
    time_stamp = datetime.now().strftime("%Y-$m-%d %H:%M:%s")
    log = f"{time_stamp} - {packet.summary()}"
    print(log)
    with open("olowu_log.txt", "a") as f:
        f.write(log + "\n")


    print("\n======================")
    print("Packet Number:", packet_count)
  

    if packet.haslayer("IP"):

        src = packet["IP"].src
        dst = packet["IP"].dst
        protocol = packet["IP"].proto

        print("Source IP:", src)
        print("Destination IP:", dst)

        if protocol == 6:
            print("Protocol: TCP")

        elif protocol == 17:
            print("Protocol: UDP")

        else:
            print("Protocol Number:", protocol)

        print(f"Payload: {bytes(packet.payload)}")


print("Starting Network Sniffer...")

sniff(prn=packet_callback, count=60)


