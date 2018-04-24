from argparse import ArgumentParser
from itertools import chain
from sys import exit
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
####################### PYSHARK HELPER FUNCTIONS START #######################
##############################################################################

def peek_into_generator(dynamo):
    '''
        PURPOSE - Determine if a 'generator' has anything to give in order
            to avoid 'hanging'
        INPUT
            dynamo - An iterable object
        OUTPUT
            If dynamo contains anything, a tuple (item[0], dynamo)
            If dynamo is empty, None
        NOTES
            This this function returns a tuple, treat tuple[1] the same
                as you would dynamo.  In fact, feel free to overwrite
                the original dynamo with tuple[1].
    '''
    ### LOCAL VARIABLES ###
    retVal = None

    ### INPUT VALIDATION ###
    if dynamo is not None:
        ### PEEK ###
        try:
            first = next(dynamo)
        except StopIteration:
            pass
        else:
            # chain() 'glues' dynamo back onto the end of "first"
            # retVal = tuple((first, dynamo))
            # The statement below was adding an extra packet
            retVal = tuple((first, chain([first], dynamo)))

    ### DONE ###
    return retVal


##############################################################################
####################### PYSHARK HELPER FUNCTIONS STOP ########################
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


def main():
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
    # cipDispFilter = ""
    cipDispFilter = "cip.service == 0x4d || cip.service == 0x4e"
    overPrefs = { 'tcp.analyze_sequence_numbers' : 'FALSE'}
    peekABoo = None  # Temp return value for peek_into_generator() calls

    ### PARSE ARGS ###
    args = parse_arguments() # Parsed arguments
    
    ### INPUT VALIDATION ###
    if args.file and args.file.__len__() > 0:
        pcapFile = os.path.join(os.getcwd(), args.file)
        # Is this actually a file?
        if not os.path.isfile(pcapFile):
            raise OSError("{} does not exist".format(pcapFile))
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

        # 1. PREPARE THE PACKET GENERATOR
        if pcapFile.__len__() > 0:
            try:
                if cipDispFilter.__len__() > 0:
                    fCapture = pyshark.FileCapture(pcapFile, override_prefs = overPrefs, display_filter = cipDispFilter)
                else:
                    fCapture = pyshark.FileCapture(pcapFile, override_prefs = overPrefs)
                            
                # packetGen = fCapture.__iter__
            except Exception as err:
                break_a_curse(stdscr)
                raise err
        elif interName.__len__() > 0:
            try:
                if cipDispFilter.__len__() > 0:
                    lCapture = pyshark.LiveCapture(interName, override_prefs = overPrefs, display_filter = cipDispFilter)
                else:
                    lCapture = pyshark.LiveCapture(interName, override_prefs = overPrefs)
                            
                # packetGen = lCapture.sniff_continuously
            except Exception as err:
                break_a_curse(stdscr)
                raise err
        else:
            raise RuntimeError("Dynamic generator logic failed")

        # 2. CHECK THE PACKET GENERATOR FOR PACKETS
        # Prepare the user for no input
        while (1):
            stdscr.addnstr(2, 2, "Waiting for packets...", printWid)
            stdscr.addnstr(3, 2, "Press [Enter] to stop waiting.", printWid)
            stdscr.refresh()

            # Give the user a chance to stop waiting for packets
            if -1 != stdscr.getch():
                try:
                    break_a_curse(stdscr)
                except Exception as err:
                    pass  # Ignore all Exceptions... pyshark gets 'barky'
                finally:
                    # exit(0)
                    raise SystemExit("User does not want to wait any longer")
            # Check for packets
            else:
                if pcapFile.__len__() > 0:
                    peekABoo = peek_into_generator(fCapture)
                elif interName.__len__() > 0:
                    peekABoo = peek_into_generator(lCapture.sniff_continuously())
                else:
                    raise RuntimeError("Dynamic generator logic failed")

                # Found a packet?
                if isinstance(peekABoo, tuple) and peekABoo.__len__() == 2:
                    # Found a packet!
                    if pcapFile.__len__() > 0:
                        packetGen = peekABoo[1]
                    elif interName.__len__() > 0:
                        packetGen = peekABoo[1]
                    else:
                        raise RuntimeError("Dynamic generator logic failed")
                    stdscr.clear()  # Clear the screen
                    stdscr.refresh()  # Update the screen
                    break
        
        # 3. ITERATE THROUGH THE PACKETS THE GENERATOR HAS TO OFFER
        for packet in packetGen:
            # 3.1. PARSE PACKETS
            # Keep track of packet number
            numPackets += 1
            # Get the "service request number"
            tmpSRN = get_cip_srn(packet)
            # Get the "session handle"
            tmpSesHndl = get_enip_session_handle(packet)
            # Get the "connection ID"
            tmpConnID = get_enip_connection_ID(packet)
            # Get the "CIP sequence count"
            tmpCSC = get_enip_CSC(packet)

            # 3.2. PRINT DATA
            # 3.2.1. Update the window
            if tmpSRN.__len__() > 0 \
            and tmpSesHndl.__len__() > 0 \
            and tmpConnID.__len__() > 0 \
            and tmpCSC.__len__() > 0:
                # Write Tag Service (0x4d)
                if tmpSRN.endswith("4d") and curr4dCSC != tmpCSC:
                    # Update the CIP sequence count
                    curr4dCSC = tmpCSC
                    # "service request number"
                    stdscr.addnstr(2, 2, tmpSRN, printWid)
                    # "session handle"
                    stdscr.addnstr(3, 2, "Session Handle - " + tmpSesHndl, printWid)
                    # "connection ID"
                    stdscr.addnstr(4, 2, "Connection ID - " + tmpConnID, printWid)
                    # "CIP sequence count"
                    stdscr.addnstr(5, 2, "Sequence Counter - " + curr4dCSC, printWid)
                # Read Modify Write Tag Service (0x4e)
                elif tmpSRN.endswith("4e") and curr4eCSC != tmpCSC:
                    # Update the CIP sequence count
                    curr4eCSC = tmpCSC
                    # "service request number"
                    stdscr.addnstr(7, 2, tmpSRN, printWid)
                    # "session handle"
                    stdscr.addnstr(8, 2, "Session Handle - " + tmpSesHndl, printWid)
                    # "connection ID"
                    stdscr.addnstr(9, 2, "Connection ID - " + tmpConnID, printWid)
                    # "CIP sequence count"
                    stdscr.addnstr(10, 2, "Sequence Counter - " + curr4eCSC, printWid)

            # Print number of packets parsed
            # Print the file for demonstration purposes
            if pcapFile.__len__() > 0:
                if pcapFile.__len__() + "Parsing file: ".__len__() > printWid:
                    stdscr.addnstr(printLen - 2, 2, "Parsing file: " 
                                   + os.path.basename(pcapFile), printWid)
                else:
                    stdscr.addnstr(printLen - 2, 2, "Parsing file: " + pcapFile, printWid)
            # Tell the user how to exit
            stdscr.addnstr(printLen - 1, 2, "Press [Enter] to stop parsing and [Enter] again to exit", printWid)
            # Print the number of packets processed
            if 1 == numPackets:
                stdscr.addnstr(printLen, 2, "Processed " + str(numPackets) + " packet", printWid)
            elif numPackets > 1:                
                stdscr.addnstr(printLen, 2, "Processed " + str(numPackets) + " packets", printWid)

            # 3.2.2. Refresh the window
            stdscr.refresh()

            # 3.2.3. Stop parsing on user input
            if -1 != stdscr.getch():
                break

        ### BREAK THE CURSE ###
        while True:
            if -1 != stdscr.getch():
                break
        break_a_curse(stdscr)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(repr(err))
    else:
        print("Done.")
