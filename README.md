# VUT-PDS

Tereza Burianová, xburia28
---------------------------------------------------------
List of files in the archive:
|xburia28
|- csv (empty folder for script purposes)
|- tests
|-- large_peers.txt
|-- small_download.txt
|-- small_init.txt
|- bt-monitor
|- bt-monitor.py
|- Readme.txt
|- xburia28.pdf
---------------------------------------------------------
The application was tested using Python 3.8.13.
A script without file extension was created, therefore the app can be run as a usual script:
./bt-monitor -pcap <pcap> -init | -peers | -download
If it does not work, try:
chmod u+x bt-monitor
Otherwise it can be run as:
./bt-monitor.py -pcap <pcap> -init | -peers | -download
python3.8 bt-monitor.py -pcap <pcap> -init | -peers | -download
---------------------------------------------------------
The latest stable release of TShark (Wireshark), which is 4.0.0 or higher, is required.
Installation is described in https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable.
Quick guide for Ubuntu:
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt-get install tshark
("universe" repository needs to be enabled: sudo add-apt-repository universe)
---------------------------------------------------------
Used modules should all be included in Python installation.
---------------------------------------------------------
Implementation and research of uTP not included, the captured pcap files contain only the TCP version.
File size estimation in -download not implemented.
