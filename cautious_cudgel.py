import pyshark


def print_ip_details(packet):
    '''
    PURPOSE - Print details from the IP header
    INPUT - pyshark Packet object
    OUTPUT - None
    '''
    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### PRINT IPV4 ###
    try:
        print("Source IP:       {}".format(packet.ip.src))
        print("Destination IP:  {}".format(packet.ip.dst))
    except AttributeError:
        # Ignore any packets missing the above
        # print("Not an IP packet!")  # DEBUGGING
        # print(packet.layers)  # DEBUGGING
        # print("{}".format(dir(packet)))  # DEBUGGING
        pass

    ### PRINT IPV6 ###
    try:
        print("Source IP:       {}".format(packet.ipv6.src))
        print("Destination IP:  {}".format(packet.ipv6.dst))
    except AttributeError:
        # Ignore any packets missing the above
        pass

    ### DONE ###
    return


def print_tcp_details(packet):
    '''
    PURPOSE - Print details from the TCP header
    INPUT - pyshark Packet object
    OUTPUT - None
    '''
    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### PRINT ###
    try:
        print("Source Port:       {}".format(packet.tcp.srcport))
        print("Destination Port:  {}".format(packet.tcp.dstport))
    except AttributeError:
        # Ignore any packets missing the above
        # print("Not a TCP packet!")  # DEBUGGING
        # print(packet.layers)  # DEBUGGING
        pass

    ### DONE ###
    return


def print_enip_details(packet):
    '''
    PURPOSE - Print details from an ENIP header
    INPUT - pyshark Packet object
    OUTPUT - None
    '''
    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### PRINT ###
    try:
        print("\n")  # Clean up
        print("ENIP Command:         {}".format(packet.enip.command))
        print("ENIP Session Handle:  {}".format(packet.enip.session))        
    except AttributeError:
        # Ignore any packets missing the above
        pass
    else:
        try:
            print_ip_details(packet)
            print_tcp_details(packet)
        except AttributeError:
            pass
    finally:
        print("\n")  # Clean up

    ### DONE ###
    return


if __name__ == "__main__":
    ### LOCAL VARIABLES ###
    

    ### WORK ###
    # 1. START LIVE CAPTURE
    # Consider using the following Wireshark display_filters in the LiveCapture() call:
    #   display_filter="enip.session"
    #   display_filter="enip.command"
    # https://wiki.wireshark.org/DisplayFilters
    # capture = pyshark.LiveCapture(interface='enp0s25')  # capture object returned by pyshark.LiveCapture()
    # capture = pyshark.LiveCapture()  # capture object returned by pyshark.LiveCapture()
    # for packet in capture.sniff_continuously():
    #     print_ip_details(packet)
    #     print_tcp_details(packet)
    #     print_enip_details(packet)
        # print("Got a packet: {}", packet)
        # print(packet)

    # 2. READ FROM STATIC FILE
    filename = "pcaps/talabor1_1.pcap"
    fcapture = pyshark.FileCapture(filename)

    for packet in fcapture:
        print_enip_details(packet)


