TLDR; you should :
1) install the NRF24 lib for your arduino IDE
2) connect your aduino & nrf24 chipset accordingly to the library documentation
3) compile/upload the script (*.ino) to your arduino
4) start the python script on your computer to talk to your arduino via usb & finally do some wireless sniffing :)

======================
=== FOLDER : NRF24 ===
======================

Arduino lib to talk to your nrf24 chipset. 
You want to copy that folder in your "libraries" folder within your arduino IDE's sketchbook folder ("~/sketchbook/libraries" on most linux).


===================================
=== nRF24SNIFF_pycontrolled.ino ===
===================================

Arduino sketch you want to compile&upload to your arduino (it uses the NRF24 patched library herein distributed, so be sure to have it in your "libraries" folder before trying to compile this sketch)

============================
=== sniffer_pycontrolled ===
============================

Folder containing a "pyserial" library, and the "nrf24_SNIFF_pycontrolled_NG.py" script. The script is used from your computer to talk to your arduino and perfom some sniffing stuff.

Usage example : 
$ python nrf24_SNIFF_pycontrolled_NG.py -p
Starting to sniff in promiscuous mode
Switching to addr : 5500
Tuned to channel 0, listenning for address.
Tuned to channel 1, listenning for address.
	['31', '76', '72', '65', '73'] appeared 6 times
Tuned to channel 2, listenning for address.
...

$ python nrf24_SNIFF_pycontrolled_NG.py -c 1 -a 3176726573
Setting channel to : 1
	OK
Setting targeted adress to : 3176726573
	OK
Starting to sniff forever.
CD051C03008000000000000000000000005A1DDA155FF0B501370AAB059E94AB
CD051C03008000000000000000000000005A1DFA2F954E65AFA87F747E59584C
CD051C03008000000000000000000000005A1DBD55A87F998BF056AAD11554B2
...


===============
=== LICENSE ===
===============
Folder NRF24 : fork of a library by Mike McCauley under the GPLV2. Our changes are also published under the GPLV2.

nRF24SNIFF_pycontrolled.ino : This arduino sketched is published under the GPLV2.

sniffer_pycontrolled : the pyserial library is published by Chris Liechti under a bsd-like license. Our script ('nrf24_SNIFF_pycontrolled_NG.py') is published under the GPLV2.
