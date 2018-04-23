from argparse import ArgumentParser
import curses
import os
import pyshark


##############################################################################
######################### ARGS HELPER FUNCTIONS START ########################
##############################################################################

def parse_arguments():
    '''
        PURPOSE - Parse argument requirements here to keep 'main' clean
        INPUT - None
        OUTPUT - Command line argument list from ArgumentParser object
    '''
    # Parser object
    parser = ArgumentParser()
    
    # Make the arguments mutually exclusive
    group = parser.add_mutually_exclusive_group(required = True)
    
    # Command line arguments
    group.add_argument("-f", "--file", type = str, help = "Pcap filename to parse")
    group.add_argument("-i", "--interface", type = str, help = "Interface name to pull a live capture")
    
    # List of arguments from the command line
    args = parser.parse_args()
    
    return args


##############################################################################
######################### ARGS HELPER FUNCTIONS STOP #########################
##############################################################################


##############################################################################
####################### CURSES HELPER FUNCTIONS START ########################
##############################################################################


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


def get_curse_dimensions(cWin):
    '''
    PURPOSE - Get the dimensions of a curses window object
    INPUT
        cWin - A curses window object
    OUTPUT
        On success, a (width, length) tuple
        On failure, None (or Exception)
    '''
    ### LOCAL VARIABLES ###
    retVal = None  # Make this into a tuple if everything succeeds
    winWid = 0  # Curses window max width
    winLen = 0  # Curses window max length

    ### INPUT VALIDATION ###
    if not cWin:
        raise TypeError("Invalid cWin")

    ### GET DIMENSIONS
    winLen, winWid = cWin.getmaxyx()

    ### DONE ###
    return (winWid, winLen)


##############################################################################
####################### CURSES HELPER FUNCTIONS STOP #########################
##############################################################################


##############################################################################
######################## ENIP HELPER FUNCTIONS START #########################
##############################################################################


def get_enip_connection_ID(packet):
    '''
    PURPOSE - Extract the connection ID from an ENIP header
    INPUT - pyshark Packet object
    OUTPUT
        On success, a string object containing the connection ID
        On failure, an empty string object
    '''
    ### LOCAL VARIABLES ###
    retVal = ""  # Will contain the ENIP connection ID if it exists

    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### EXRACT DATA ###
    try:
        # retVal = packet.enip.connid  # This is a guess since I'm offline
        retVal = packet.enip.cpf_cai_connid  # THIS is it
    except AttributeError:
        pass

    ### DONE ###
    return retVal


def get_enip_session_handle(packet):
    '''
    PURPOSE - Extract the session handle from an ENIP header
    INPUT - pyshark Packet object
    OUTPUT
        On success, a string object containing the session handle
        On failure, an empty string object
    '''
    ### LOCAL VARIABLES ###
    retVal = ""  # Will contain the ENIP session if it exists

    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### EXRACT DATA ###
    try:
        retVal = packet.enip.session
    except AttributeError:
        pass

    ### DONE ###
    return retVal


def get_enip_CSC(packet):
    '''
    PURPOSE - Extract the CIP sequence count from an ENIP header
    INPUT - pyshark Packet object
    OUTPUT
        On success, a string object containing the CIP sequence count
        On failure, an empty string object
    '''
    ### LOCAL VARIABLES ###
    retVal = ""  # Will contain the ENIP sequence count if it exists

    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### EXRACT DATA ###
    try:
        retVal = packet.enip.cpf_cdi_seqcnt
    except AttributeError:
        pass

    ### DONE ###
    return retVal


##############################################################################
######################## ENIP HELPER FUNCTIONS STOP ##########################
##############################################################################


##############################################################################
######################### CIP HELPER FUNCTIONS START #########################
##############################################################################


def get_cip_srn(packet):
    '''
    PURPOSE - Extract the service request number from a CIP header
    INPUT - pyshark Packet object
    OUTPUT
        On success, a string object containing the service request number
        On failure, an empty string object
    '''
    ### LOCAL VARIABLES ###
    retVal = ""  # Will contain the CIP SRN if it exists

    ### INPUT VALIDATION ###
    if not isinstance(packet, pyshark.packet.packet.Packet):
        raise ValueError("Invalid packet type")

    ### EXRACT DATA ###
    try:
        retVal = packet.cip.service
    except AttributeError:
        pass

    ### DONE ###
    return retVal


##############################################################################
######################### CIP HELPER FUNCTIONS STOP ##########################
##############################################################################


if __name__ == "__main__":
    ### LOCAL VARIABLES ###
    pcapFile = ""  # Filename to pyshark.FileCapture from
    interName = ""  # Interface name to pyshark.LiveCapture from
    tmpSesHndl = ""  # Temp variable to hold the ENIP session handle
    tmpConnID = ""  # Temp variable to hold the ENIP connection ID
    tmpSRN = ""  # Temp variable to hold the CIP service request number
    tmpCSC = ""  # Temp variable to hold the CIP sequence count
    curr4dCSC = ""  # Current 0x4d CIP sequence count
    curr4eCSC = ""  # Current 0x4d CIP sequence count
    maxWid = 0  # Maximum width of the curses window
    maxLen = 0  # Maximum length of the curses window
    printWid = 0  # Maximum printable area of the curses window
    printLen = 0  # Maximum printable area of the curses window
    numPackets = 0  # Keep track of the number of packets
    # Wireshark display filter for specific "service request numbers"
    cipDispFilter = ""
    # cipDispFilter = "cip.service == 0x4d || cip.service == 0x4e"

    ### PARSE ARGS ###
    args = parse_arguments() # Parsed arguments
    
    ### INPUT VALIDATION ###
    if args.file and args.file.__len__() > 0:
        pcapFile = args.file
    elif args.interface and args.interface.__len__() > 0:
        interName = args.interface
    else:
        raise RuntimeError("Received invalid arguments")
    
    ### WORK ###
    stdscr = curse_a_win()  # Initialize a curses window
    if stdscr:
        # 0. GET CURSES WINDOW DIMENSIONS
        maxWid, maxLen = get_curse_dimensions(stdscr)

        if maxWid < 1 or maxLen < 1:
            break_a_curse(stdscr)
            raise RuntimeError("get_curse_dimensions appears to have failed")
        elif maxWid < (29 + 4) or maxLen < (13 + 4):
            break_a_curse(stdscr)
            raise RuntimeError("Terminal window is too small")
        else:
            printWid = maxWid - 4
            printLen = maxLen - 4

        ######################################################################
        ######################################################################
        ######################################################################
        # 1. GET PACKETS
        if pcapFile.__len__() > 0:
            if cipDispFilter.__len__() > 0:
                fCapture = pyshark.FileCapture(pcapFile, display_filter = cipDispFilter)
            else:
                fCapture = pyshark.FileCapture(pcapFile)
                        
            packetGen = fCapture.__iter__
        elif interName.__len__() > 0:
            if cipDispFilter.__len__() > 0:
                lCapture = pyshark.LiveCapture(interName, display_filter = cipDispFilter)
            else:
                lCapture = pyshark.LiveCapture(interName)
                        
            packetGen = lCapture.sniff_continuously
        else:
            raise RuntimeError("Dynamic generator logic failed")
        
        for packet in packetGen():
            # 2. PARSE PACKETS
            # 2.0. Keep track of packet number
            numPackets += 1
            # 2.1. Get the "service request number"
            tmpSRN = get_cip_srn(packet)
            # 2.2. Get the "session handle"
            tmpSesHndl = get_enip_session_handle(packet)
            # 2.3. Get the "connection ID"
            tmpConnID = get_enip_connection_ID(packet)
            # 2.4. Get the "CIP sequence count"
            tmpCSC = get_enip_CSC(packet)

            # 3. PRINT DATA
            # 3.1. Update the window
            if tmpSRN.__len__() > 0 \
            and tmpSesHndl.__len__() > 0 \
            and tmpConnID.__len__() > 0 \
            and tmpCSC.__len__() > 0:
                # 3.1.1. Write Tag Service (0x4d)
                if tmpSRN.endswith("4d") and curr4dCSC != tmpCSC:
                    # 3.1.1.0. Update the CIP sequence count
                    curr4dCSC = tmpCSC
                    # 3.1.1.1. "service request number"
                    stdscr.addnstr(2, 2, tmpSRN, printWid)
                    # 3.1.1.2. "session handle"
                    stdscr.addnstr(3, 2, "Session Handle - " + tmpSesHndl, printWid)
                    # 3.1.1.3. "connection ID"
                    stdscr.addnstr(4, 2, "Connection ID - " + tmpConnID, printWid)
                    # 3.1.1.4. "CIP sequence count"
                    stdscr.addnstr(5, 2, "Sequence Counter - " + curr4dCSC, printWid)
                # 3.1.2. Read Modify Write Tag Service (0x4e)
                elif tmpSRN.endswith("4e") and curr4eCSC != tmpCSC:
                    # 3.1.1.0. Update the CIP sequence count
                    curr4eCSC = tmpCSC
                    # 3.1.1.1. "service request number"
                    stdscr.addnstr(7, 2, tmpSRN, printWid)
                    # 3.1.1.2. "session handle"
                    stdscr.addnstr(8, 2, "Session Handle - " + tmpSesHndl, printWid)
                    # 3.1.1.3. "connection ID"
                    stdscr.addnstr(9, 2, "Connection ID - " + tmpConnID, printWid)
                    # 3.1.1.3. "CIP sequence count"
                    stdscr.addnstr(10, 2, "Sequence Counter - " + curr4eCSC, printWid)

            # 3.1.3. Print number of packets parsed
            # 3.1.3.1. Print the file for demonstration purposes
            if pcapFile.__len__() > 0:
                if pcapFile.__len__() + "Parsing file: ".__len__() > printWid:
                    stdscr.addnstr(printLen - 2, 2, "Parsing file: " 
                                   + os.path.basename(pcapFile), printWid)
                else:
                    stdscr.addnstr(printLen - 1, 2, "Parsing file: " + pcapFile, printWid)
            # 3.1.3.2. Tell the user how to exit
            stdscr.addnstr(printLen - 1, 2, "Press [Enter] to stop parsing and [Enter] again to exit", printWid)
            # 3.1.3.3. Print the number of packets processed
            stdscr.addnstr(printLen, 2, "Processed " + str(numPackets) + " packets", printWid)

            # 3.2. Refresh the window
            stdscr.refresh()

            # N. Stop parsing on user input
            if -1 != stdscr.getch():
                break

        ### BREAK THE CURSE ###
        # This is only needed for FileCapture()
        # LiveCapture() will theoretically go on forever
        while True:
            if -1 != stdscr.getch():
                break
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


# def dynamic_execution(pcapFile, interName, dispFilter):
#     '''
#         PURPOSE - Dynamically choose 'packet' generator
#         INPUT
#             pcapFile - pcap filename
#             interName - Interface name
#             dispFilter - Display filter
#         OUTPUT
#             On success, packet generator
#     '''
#     ### LOCAL VARIABLES ###
#     retVal = None
    
#     ### INPUT VALIDATION ###
#     if not isinstance(pcapFile, str):
#         raise TypeError("pcapFile is not a string")
#     elif not isinstance(interName, str):
#         raise TypeError("interName is not a string")
#     elif not isinstance(dispFilter, str):
#         raise TypeError("dispFilter is not a string")
#     elif pcapFile.__len__() > 0 and intername.__len__() > 0:
#         raise ValueError("Unable to process both pcap files and live capture")
                        
#     ### DECIDE ###
#     if pcapFile.__len__() > 0:
#         if dispFilter.__len__() > 0:
#             yield pyshark.FileCapture(pcapFile, display_filter = dispFilter)
#         else:
#             yield pyshark.FileCapture(pcapFile)
#     elif interName.__len__() > 0:
#         if dispFilter.__len__() > 0:
#             yield pyshark.LiveCapture(interName, display_filter = dispFilter)
#         else:
#             yield pyshark.LiveCapture(interName)

#     ### DONE ###
#     return retVal  