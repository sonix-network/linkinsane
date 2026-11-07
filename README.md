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

Each check waits about half a second for the receiver's copy, counted from
when it sent. With a slow receiver or a long out-of-band path (VMs, for
example), `--grace 3` gives every check that much longer.
`--sequential` runs one check at a time, so the broadcast check's burst
cannot drown the frames of the checks that run next at a slow receiver.

Ensure that the peers can communicate out of band and the IP you provide to inquisitor
can be reached regardless of the IXP platform.

The receive-window regression tests use a deterministic queue and clock, without
network interfaces or packet transmission:

```sh
python3 -m unittest discover -s tests -v
```
