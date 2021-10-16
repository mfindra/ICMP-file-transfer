#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

// network libs
#include <ifaddrs.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
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

// return struct with IPv4 or IPv6 address stats
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    } else if (sa->sa_family == AF_INET6) {
        return &(((struct sockaddr_in6 *)sa)->sin6_addr);
    }
}

u_int16_t icmp_cksum(uint16_t *buffer, int length) {
    uint32_t sum = 0;
    uint16_t *buf = buffer;
    uint16_t answer = 0;

    // Adding up all 16 bits in sum
    for (answer = 0; length > 1; length -= 2) {
        sum += *buf;
        buf++;
    }

    // Even length - add last byte
    if (length == 1) {
        sum += *(uint16_t *)buf;
    }

    // one complement of result
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int main(int argc, char **argv) {
    int DEBUG = 1;
    string R_opt;
    string S_opt;
    bool L_opt = false;
    int opt;

    /*
    int sock;
    int on;
    char src_name[256];
    string send_buf;
    char recv_buf[300];
    struct ip *ip = (struct ip *)send_buf.c_str();
    struct icmp *icmp = (struct icmp *)(ip + 1);
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in src, dst;
    int dst_addr_len;
    struct timeval t;
    fd_set socks;
    int failed_count = 0;
    int bytes_sent, bytes_recv;
    int result;
    */

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
                return EXIT_FAILURE;
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
            return EXIT_FAILURE;
        }

        // filter compilation
        if (pcap_compile(handler, &fp, filter_string.c_str(), 0, netp) == -1) {
            fprintf(stderr, "Error calling pcap_compile\n");
            return EXIT_FAILURE;
        }

        // set filter
        if (pcap_setfilter(handler, &fp) == -1) {
            fprintf(stderr, "Error setting filter\n");
            return EXIT_FAILURE;
        }

        // loop callback function
        pcap_loop(handler, 1, callback_handler, NULL);

        // memory cleanup
        pcap_freecode(&fp);
        pcap_close(handler);
        cout << endl;

        return 0;
    } else {
        struct addrinfo hints, *server_info, *p;
        int status, protocol;
        char ip_string[INET6_ADDRSTRLEN];

        // check arguments in sender mode
        if (R_opt.empty()) {
            fprintf(stderr, "ERROR - Missing file name!\n");
            return EXIT_FAILURE;
        } else if (S_opt.empty()) {
            fprintf(stderr, "ERROR - Missing IP address or hostname!\n");
            return EXIT_FAILURE;
        }

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((status = getaddrinfo(S_opt.c_str(), NULL, &hints, &server_info)) != 0) {
            fprintf(stderr, "%s\n", gai_strerror(status));
            return 1;
        }

        // resolve ip address from domain name if necessary
        inet_ntop(server_info->ai_family, get_in_addr(server_info->ai_addr), ip_string, sizeof ip_string);

        if (DEBUG) {
            cout << "ip address for " << S_opt << ": " << ip_string << endl;
        }

        // select protocol
        if (server_info->ai_family == AF_INET)
            protocol = IPPROTO_ICMP;
        else
            protocol = IPPROTO_ICMPV6;

        // create socket
        cout << server_info->ai_family << server_info->ai_socktype << protocol << endl;

        int sock = socket(server_info->ai_family, server_info->ai_socktype, protocol);
        if (sock == -1) {
            fprintf(stderr, "Error createing socket:  %s\n", gai_strerror(status));
            return 1;
        }

        /*
        // read file into buffer
        ifstream f(R_opt.c_str());
        if (f.good()) {
        cout << "File extists" << endl;
        } else {
        fprintf(stderr, "ERROR - File not found\n");
        return EXIT_FAILURE;
        }

        f.close();

        // create header
        ip->ip_v = 4;
        ip->ip_hl = 5;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(send_buf.c_str()));
        ip->ip_id = htons(321);
        ip->ip_off = htons(0);
        ip->ip_ttl = 255;
        ip->ip_p = IPPROTO_ICMP;
        ip->ip_sum = 0;

        // Get source IP address
        if (gethostname(src_name, sizeof(src_name)) < 0) {
        perror("gethostname() error");
        exit(EXIT_FAILURE);
        } else {
        if ((src_hp = gethostbyname(src_name)) == NULL) {
        fprintf(stderr, "%s: Can't resolve, unknown source.\n", src_name);
        exit(EXIT_FAILURE);
        } else
        ip->ip_src = (*(struct in_addr *)src_hp->h_addr);
        }

        // Get destination IP address
        if ((dst_hp = gethostbyname(S_opt.c_str())) == NULL) {
        if ((ip->ip_dst.s_addr = inet_addr(S_opt.c_str())) == -1) {
        fprintf(stderr, "%s: Can't resolve, unknown destination.\n", S_opt.c_str());
        exit(EXIT_FAILURE);
        }
        } else {
        ip->ip_dst = (*(struct in_addr *)dst_hp->h_addr);
        dst.sin_addr = (*(struct in_addr *)dst_hp->h_addr);
        }

        if (DEBUG) {
        cout << inet_ntoa(ip->ip_src) << endl;
        cout << inet_ntoa(ip->ip_dst) << endl;
        }

        // create ICMP packet
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = 111;
        icmp->icmp_seq = 0;

        // Create RAW socket
        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() error");
        return EXIT_FAILURE;
        }

        // Socket options, tell the kernel we provide the IP structure
        on = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() for IP_HDRINCL error");
        exit(EXIT_FAILURE);
        }

        dst.sin_family = AF_INET;
        dst_addr_len = sizeof(dst);

        t.tv_sec = 5;
        t.tv_usec = 0;

        // Set socket listening descriptors
        FD_ZERO(&socks);
        FD_SET(sock, &socks);

        //send_buf.assign("hahahahahahahah");

        // Send packet
        if ((bytes_sent = sendto(sock, send_buf.c_str(), sizeof(send_buf), 0,
                         (struct sockaddr *)&dst, dst_addr_len)) < 0) {
        perror("sendto() error");
        failed_count++;
        printf("Failed to send packet.\n");
        fflush(stdout);
        } else {
        printf("Sent %d byte packet... ", bytes_sent);

        fflush(stdout);

        // Listen for the response or timeout
        if ((result = select(sock + 1, &socks, NULL, NULL, &t)) < 0) {
        perror("select() error");
        failed_count++;
        printf("Error receiving packet!\n");
        } else if (result > 0) {
        printf("Waiting for packet... ");
        fflush(stdout);

        if ((bytes_recv = recvfrom(sock, recv_buf,
                                   sizeof(ip) + sizeof(icmp) + sizeof(recv_buf), 0,
                                   (struct sockaddr *)&dst,
                                   (socklen_t *)&dst_addr_len)) < 0) {
            perror("recvfrom() error");
            failed_count++;
            fflush(stdout);
        } else
            printf("Received %d byte packet!\n", bytes_recv);
        } else {
        printf("Failed to receive packet!\n");
        failed_count++;
        }

        fflush(stdout);

        icmp->icmp_seq++;
        }
        //close socket
        close(sock);*/

        if (DEBUG) {
            cout << "R_opt = " << R_opt << endl;
            cout << "S_opt = " << S_opt << endl;
            cout << "L_opt = " << L_opt << endl;
        }
    }
    return EXIT_SUCCESS;
}