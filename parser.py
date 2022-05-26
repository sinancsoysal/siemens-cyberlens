import json

import pyshark
import time

# define interface
networkInterface = "Wi-Fi"
filter = "tcp port 2404"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface, bpf_filter=filter)

print("listening on %s" % networkInterface)


# true = medium, false = high
def isValid(packet):
    isInvalid = packet.__contains__("Invalid")
    isIndeterminate = packet.__contains__("Indeterminate")

    # print(isInvalid)
    # print(isIndeterminate)

    if isInvalid and isIndeterminate:
        return False
    return True


if __name__ == "__main__":

    file = open("captured.txt", "w")

    for packet in capture.sniff_continuously():
        # adjusted output
        try:
            # get timestamp
            localtime = time.asctime(time.localtime(time.time()))

            # get packet content
            protocol = packet.transport_layer  # protocol type
            src_addr = packet.ip.src  # source address
            src_port = packet[protocol].srcport  # source port
            dst_addr = packet.ip.dst  # destination address
            dst_port = packet[protocol].dstport  # destination port

            # output packet info
            # print("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))

            # res = False
            res = isValid(str(packet))
            if res is False:
                info = {'alert': 'Problem',
                        'time': localtime,
                        'source': src_addr,
                        'sourceCountry': "TR",
                        'target': "TR",
                        'port': dst_port,
                        'type': "unknown",
                        'alertClass': 'low',
                        'destinationIP': dst_addr,
                        }
                file.write(json.dumps(info) + ",")
                file.flush()
        except AttributeError as e:
            # ignore packets other than TCP, UDP and IPv4
            pass

    file.close()
