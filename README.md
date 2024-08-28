# linkinsane

THIS IS JUST A PLAYGROUND FOR NOW, HOPEFULLY IT WILL BE USEFUL SOON (TM)

## Requirements

On EL9:

 * python3-coloredlogs
 * python3-scapy
 * python3-zmq
 * libpcap

## Usage

 * Start `sudo receiver.py eth0` on one of the peers
 * Start `sudo inquisitor.py eth0 <first-peer-IP>` on another peer

Ensure that the peers can communicate out of band and the IP you provide to inquisitor
can be reached regardless of the IXP platform.
