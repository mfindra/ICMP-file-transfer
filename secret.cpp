#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

// network libs
#include <ifaddrs.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

// other libs
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <ctime>
#include <sstream>

using namespace std;

void PrintHelp() {
    cout << "FILE TRANSFER USING SECRET CHANNEL - ISA PROJECT 2021" << endl;
    cout << "======================================================" << endl
         << endl;
    cout << "Descrition: " << endl;
    cout << "Arguments: -r               : file to transfer " << endl;
    cout << "           -s <IP|Hostname> : destination IP address or hostname " << endl;
    cout << "           -l               : runs as server, which listens for incoming ICMP" << endl;
    cout << "                              messages and stores them in current directory" << endl;
    cout << endl;
    cout << "Example usage: " << endl;
}

void callback_handler(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // initialize variable for output print
    stringstream ss;

    // ipv4
    struct in_addr addr_src_tmp;
    string ip_src_tmp = "";
    struct in_addr addr_dest_tmp;
    string ip_dest_tmp = "";

    //ipv6
    string ip6_dest_addr;
    string ip6_src_addr;

    const u_char *packet_totlen = packet + ETH_HLEN;
    ether_header *eth_header = (ether_header *)packet;
    u_short ethertype = htons(eth_header->ether_type);

    // process ether type
    switch (ethertype) {
        // process IPv4 packet
        case ETHERTYPE_IP: {
            // get packet header
            const struct iphdr *ip_header =
                (struct iphdr *)(packet + sizeof(struct ethhdr));

            // save source and destination ip adress
            addr_src_tmp.s_addr = ip_header->saddr;
            addr_dest_tmp.s_addr = ip_header->daddr;

            // protocol switch (UDP, TCP, ICMP)
            switch (ip_header->protocol) {
                case IPPROTO_ICMP: {
                    // save source and destination port
                    ip_src_tmp = "";
                    ip_dest_tmp = "";
                    break;
                }
                default:
                    // filter removes other types
                    break;
            }
            break;
        }
    }

    // print source ip and port
    if (ip6_src_addr != "")
        cout << " " << ip6_src_addr;
    else
        cout << " " << inet_ntoa(addr_src_tmp);
    if (ip_src_tmp != "")
        cout << " : " << ip_src_tmp;

    // print destination ip address and port
    if (ip6_dest_addr != "")
        cout << " > " << ip6_dest_addr;
    else
        cout << " > " << inet_ntoa(addr_dest_tmp);
    if (ip_dest_tmp != "")
        cout << " : " << ip_dest_tmp;

    // print length of recieved packet
    cout << " length " << pkthdr->len << " bytes" << endl;

    // print packet data
    for (unsigned int i = 0; i < pkthdr->caplen; i++) {
        if (i % 16 == 0) {
            cout << "  " << ss.str();
            ss = stringstream();
            printf("\n0x%04x: ", i);
        }
        printf("%x%x ", (packet[i] >> 4) & 15, packet[i] & 15);

        // print character if possible else "."
        if (isprint(packet[i])) {
            ss << packet[i];
        } else {
            ss << ".";
        }

        // align last row
        if (i == pkthdr->caplen - 1) {
            printf("%*c", (16 - i % 16) * 3 - 2, ' ');
            cout << " " << ss.str() << flush;
        }
    }
    cout << endl;
}

int main(int argc, char **argv) {
    int DEBUG = 1;

    string R_opt;
    string S_opt;
    bool L_opt = false;

    int opt;
    while ((opt = getopt(argc, argv, "r:s:lh")) != -1) {
        switch (opt) {
            case 'r':
                R_opt = optarg;
                break;
            case 's':
                S_opt = optarg;
                break;
            case 'l':
                L_opt = true;
                break;
            case 'h':
                PrintHelp();
                return 0;
                break;
            default:
                fprintf(stderr, "ERROR - Wrong argument!\n");
                return 1;
        }
    }

    // check if application runs in listen (-l) mode
    if (L_opt) {
        cout << "Listen mode" << endl;

        string filter_string = "icmp or icmp6";

        char errbuf[PCAP_ERRBUF_SIZE];

        // get network interface address and mask
        pcap_t *handler;
        struct bpf_program fp;
        string interface = "enp0s3";
        bpf_u_int32 maskp;
        bpf_u_int32 netp;

        pcap_lookupnet(interface.c_str(), &netp, &maskp, errbuf);

        // open device for reading in promiscuous mode
        handler = pcap_open_live(interface.c_str(), BUFSIZ, 1, -1, errbuf);
        if (handler == NULL) {
            fprintf(stderr, "Error - pcap_open_live(): %s\n", errbuf);
            return 1;
        }

        // filter compilation
        if (pcap_compile(handler, &fp, filter_string.c_str(), 0, netp) == -1) {
            fprintf(stderr, "Error calling pcap_compile\n");
            return 1;
        }

        // set filter
        if (pcap_setfilter(handler, &fp) == -1) {
            fprintf(stderr, "Error setting filter\n");
            return 1;
        }

        // loop callback function
        pcap_loop(handler, 1, callback_handler, NULL);

        // memory cleanup
        pcap_freecode(&fp);
        pcap_close(handler);
        cout << endl;

        return 0;
    } else {
        // check arguments in sender mode
        if (R_opt.empty()) {
            fprintf(stderr, "ERROR - Missing file name!\n");
            return 1;
        } else if (S_opt.empty()) {
            fprintf(stderr, "ERROR - Missing IP address or hostname!\n");
            return 1;
        }

        //
        ifstream f(R_opt.c_str());
        if (f.good()) {
            cout << "File extists" << endl;
        } else {
            fprintf(stderr, "ERROR - File not found\n");
            return 1;
        }

        f.close();
    }

    if (DEBUG) {
        cout << "R_opt = " << R_opt << endl;
        cout << "S_opt = " << S_opt << endl;
        cout << "L_opt = " << L_opt << endl;
    }

    return 0;
}