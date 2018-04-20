import curses
import pyshark


def curse_a_win():
    '''
    PURPOSE - Initialize a curses window
    INPUT - None
    OUTPUT - 
        On success, an initialzied window object
        On failure, None (or Exception)
    NOTES
        Any modifications to the window initialization need to be reflected
            in break_a_curse()
    '''
    ### INIT A WINDOW ###
    # 1. Initialize curses
    stdscr = curses.initscr()

    if stdscr:
        ### CONFIGURE THE WINDOW ###
        # 2. Turn off automatic echoing of keys to the screen
        curses.noecho()
        # 3. React to keys instantly
        curses.cbreak()
        # 4. Set non-blocking read
        stdscr.timeout(0)

    ### DONE ###
    return stdscr


def break_a_curse(cWin):
    '''
    PURPOSE - Terminate a curses window and restore the terminal
    INPUT
        cWin - A curses window object
    OUTPUT - None
    '''
    ### LOCAL VARIABLES ###
    retVal = True  # Make this False if anyting fails

    ### TERMIANTE A WINDOW ###
    # 1. Turn off cbreak
    curses.nocbreak()
    # 2. Restore echo
    curses.noecho()
    # 3. Restore the terminal
    curses.endwin()

    ### DONE ###
    return


if __name__ == "__main__":
    ### LOCAL VARIABLES ###
    stdscr = curse_a_win()  # Initialize a curses window

    ### WORK ###
    if stdscr:
        # 1. GET PACKETS
        # 1.1. Real input
        # capture = pyshark.LiveCapture()
        # for packet in capture.sniff_continuously():
        # 1.1. Test input
        filename = "pcaps/talabor1_1.pcap"
        fcapture = pyshark.FileCapture(filename)
        for packet in fcapture:
            pass

        # Time to end?
        while -1 == stdscr.getch():
            continue

        ### BREAK THE CURSE ###
        break_a_curse(stdscr)










### OLD FUNCTIONS ###
# def print_ip_details(packet):
#     '''
#     PURPOSE - Print details from the IP header
#     INPUT - pyshark Packet object
#     OUTPUT - None
#     '''
#     ### INPUT VALIDATION ###
#     if not isinstance(packet, pyshark.packet.packet.Packet):
#         raise ValueError("Invalid packet type")

#     ### PRINT IPV4 ###
#     try:
#         print("Source IP:       {}".format(packet.ip.src))
#         print("Destination IP:  {}".format(packet.ip.dst))
#     except AttributeError:
#         # Ignore any packets missing the above
#         # print("Not an IP packet!")  # DEBUGGING
#         # print(packet.layers)  # DEBUGGING
#         # print("{}".format(dir(packet)))  # DEBUGGING
#         pass

#     ### PRINT IPV6 ###
#     try:
#         print("Source IP:       {}".format(packet.ipv6.src))
#         print("Destination IP:  {}".format(packet.ipv6.dst))
#     except AttributeError:
#         # Ignore any packets missing the above
#         pass

#     ### DONE ###
#     return


# def print_tcp_details(packet):
#     '''
#     PURPOSE - Print details from the TCP header
#     INPUT - pyshark Packet object
#     OUTPUT - None
#     '''
#     ### INPUT VALIDATION ###
#     if not isinstance(packet, pyshark.packet.packet.Packet):
#         raise ValueError("Invalid packet type")

#     ### PRINT ###
#     try:
#         print("Source Port:       {}".format(packet.tcp.srcport))
#         print("Destination Port:  {}".format(packet.tcp.dstport))
#     except AttributeError:
#         # Ignore any packets missing the above
#         # print("Not a TCP packet!")  # DEBUGGING
#         # print(packet.layers)  # DEBUGGING
#         pass

#     ### DONE ###
#     return


# def print_enip_details(packet):
#     '''
#     PURPOSE - Print details from an ENIP header
#     INPUT - pyshark Packet object
#     OUTPUT - None
#     '''
#     ### INPUT VALIDATION ###
#     if not isinstance(packet, pyshark.packet.packet.Packet):
#         raise ValueError("Invalid packet type")

#     ### PRINT ###
#     try:
#         print("\n")  # Clean up
#         print("ENIP Command:         {}".format(packet.enip.command))
#         print("ENIP Session Handle:  {}".format(packet.enip.session))        
#     except AttributeError:
#         # Ignore any packets missing the above
#         pass
#     else:
#         try:
#             print_ip_details(packet)
#             print_tcp_details(packet)
#         except AttributeError:
#             pass
#     finally:
#         print("\n")  # Clean up

#     ### DONE ###
#     return