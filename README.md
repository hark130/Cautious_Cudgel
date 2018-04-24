# Cautious_Cudgel
Utilizing pyshark to inspect Allen-Bradley Logix 5000 Controller Common Industrial Protocol (CIP) traffic.

## REFERENCES
* [Source controlled documents](https://github.com/hark130/Cautious_Cudgel/tree/master/Research_Files)
* [Wirehsark Display Filter Reference: Common Industrial Protocol](https://www.wireshark.org/docs/dfref/c/cip.html)

## SETUP

See the [Install instructions](https://github.com/hark130/Cautious_Cudgel/wiki/Install_Instructions) on the [Cautious Cudgel wiki](https://github.com/hark130/Cautious_Cudgel/wiki)

## FACTS

* Uses TCP and UDP ports 44818 (I/O messages)
* Uses TCP and UDP ports 2222 (implicit and explicit messaging on client/server messaging)
* Wireshark filters for session handle
    * enip.session
    * enip.command
    * cip.service
* Attempt to override the pyshark::Capture class's default parameters by setting tcp.analyze_sequence_numbers to false in the ctor
   * tshark:  ```... -o tcp.analyze_sequence_numbers:false ...```
   * pyshark?:  ```Capture(override_prefs={'tcp.analyze_sequence_numbers': 'FALSE'})```
