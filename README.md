# Cautious_Cudgel
Utilizing pyshark to inspect traffic

## FACTS

* Uses TCP and UDP ports 44818 (I/O messages)
* Uses TCP and UDP ports 2222 (implicit and explicit messaging on client/server messaging)
* Wireshark filters for session handle
    * enip.session
    * enip.command
