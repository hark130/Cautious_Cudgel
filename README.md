# Cautious_Cudgel
Utilizing pyshark to inspect traffic

## REFERENCES
* [Wirehsark Display Filter Reference: Common Industrial Protocol](https://www.wireshark.org/docs/dfref/c/cip.html)

## SETUP

* ```apt install tshark```
* ```pip3 install pyshark==0.3.6.2```
* ```chmod u+s /usr/bin/dumpcap```
* ```python cautious_cudgel.py```

## FACTS

* Uses TCP and UDP ports 44818 (I/O messages)
* Uses TCP and UDP ports 2222 (implicit and explicit messaging on client/server messaging)
* Wireshark filters for session handle
    * enip.session
    * enip.command
