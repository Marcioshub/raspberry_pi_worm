# Raspberry Pi Worm (For educational purposes only)

A mostly harmless worm made for the raspberry pi. It will attempt to connect
via ssh (port 22) to hosts it receives from arp (Address Resolution Protocol).
When successful it will save known remote hosts and passwords to a hosts.txt
file for faster future reconnections. This worm will primary attempt to brute
force the ssh port with a wordlist for the raspberry pi and repeat the process
every 15 minutes via the saved cron job.

## Installation

Ensure that the rpi has paramiko installed for ssh.

```bash
pip3 install -r requirements.txt
or
pip3 install paramiko
```

## Usage

```bash
python3 worm.py <ip addresss of this rpi> <password of this rpi>
```
