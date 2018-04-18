import pyshark


if __name__ == "__main__":
    ### LOCAL VARIABLES ###
    capture  # capture object returned by pyshark.LiveCapture()
    
    # Placeholder
    print("We started at the bottom.  Now we're here!")
    
    # 1. START LIVE CAPTURE
    # Consider using the following Wireshark display_filters in the LiveCapture() call:
    #   display_filter="enip.session"
    #   display_filter="enip.command"
    # https://wiki.wireshark.org/DisplayFilters
    capture = pyshark.LiveCapture()
    for packet in capture.sniff_continuously():
        print("Got a packet: {}", packet)
        print("Source IP: {}", packet[2].src)
        print("Dest IP:   {}", packet[2].dst)
    
