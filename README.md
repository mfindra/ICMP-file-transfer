# ICMP encrypted file transferer

File transfer using encrypted ICMP packets.


## Description 

Transferring file from client to client using ICMP or ICMPv6 packets. 
If file is greater than packet size, file is divided into more packets.
Message is transferred in ICMP tail, where some space is left empty. 

Message is encoded using 128-bit AES cipher in 16B blocks using `openssl` library. 
If IP destination address is IPv6, corresponding packets are created. Free space in the packet is divided and padded with 0, and after the ICMP packet is received it is discarded. All fields need to be filled out properly including  `checksum`. 

First packet transferred only holds information about message which is being transferred (identifier, name length, padding).

After receiving the file is stored in receiver current working directory. 

This implementation does not take into consideration any packet loss. 

```
Arguments:
           -r                            : file to transfer 
           -s <IP|Hostname>  : destination IP address or hostname 
           -l                            : runs as server, which listens for incoming ICMP
                                           messages and stores them in current directory
           -h                            : prints help
```
## Usage

### Build

Compile binary file using makefile.

    make

### Receiver

After all files are transferred, receiver needs to stop receiving using Ctrl+C (SIGINT)!

Receiving file example_file.txt from address 192.168.0.1

    sudo ./secret - l 

### Sender 

Sending file example_file.txt to address 192.168.0.1

    sudo ./secret -r example_file.txt -s 192.168.0.1

After file is sent, program ends. 

## Note

More info about this implementation available in *manual.pdf* in czech language. 

