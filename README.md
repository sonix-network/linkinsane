# linkinsane

Status: Kind of works!

![image](https://github.com/user-attachments/assets/74169443-ac42-4e2c-98bb-bb0bdedf97f3)


## Requirements

On EL9:

 * python3-coloredlogs
 * python3-scapy
 * python3-zmq
 * libpcap
 * tcpreplay

## Usage

 * Start `sudo receiver.py eth0` on one of the peers
 * Start `sudo inquisitor.py eth0 <first-peer-IP>` on another peer

The unicast checks send to random destination MACs, which the receiver sees
in promiscuous mode. When the receiver's NIC only gets frames for its own MAC
(a VM behind a hypervisor that filters on the guest MAC, for example), pass
the receiver's MAC with `--dst-mac aa:bb:cc:dd:ee:ff`.

Ensure that the peers can communicate out of band and the IP you provide to inquisitor
can be reached regardless of the IXP platform.
