/*
autor: Michal Findra, xfindr00
project: ISA 
description: File transfer using encrypted ICMP packets.
*/
#include <openssl/aes.h>
#include <unistd.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

// network libs
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
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
#include <vector>

#define PACKET_SIZE 1400
#define DEBUG 1
#define KEY_LENGTH 128
#define FILTER_STRING "icmp[icmptype] = icmp-echo or icmp6[icmp6type] = icmp6-echo"
#define ICMP_PACKET_ID 0x0abc

using namespace std;

void PrintHelp() {
    cout << "FILE TRANSFER USING ENCRYPTED ICMP PACKETS - ISA PROJECT 2021" << endl;
    cout << "======================================================" << endl
         << endl;
    cout << "Descrition: Transfering file from client to client using ICMP or ICMPv6 packets." << endl
         << "If file is greater than packet size, file is divided into more packets." << endl;
    cout << "Arguments: -r               : file to transfer " << endl;
    cout << "           -s <IP|Hostname> : destination IP address or hostname " << endl;
    cout << "           -l               : runs as server, which listens for incoming ICMP" << endl;
    cout << "                              messages and stores them in current directory" << endl;
    cout << "           -h               : print help" << endl;
    cout << endl;
    cout << "Example usage: " << endl
         << endl;
    cout << "Sending file \"example_file.txt\" to address 192.168.0.1 :" << endl;
    cout << "       server: sudo ./secret -r example_file.txt -s 192.168.0.1" << endl
         << "       reciever: sudo ./secret - l" << endl;
}

// decrypt _message of size _message_len using AES cypher with 128 bit key length
char *decrypt_message(char *_message, int _message_len) {
    // setup decryption key
    AES_KEY decrypt_key;
    AES_set_decrypt_key((const unsigned char *)"xfindr00", KEY_LENGTH, &decrypt_key);
    unsigned char *output = (unsigned char *)calloc(_message_len, 1);

    for (int i = 0; i < _message_len; i += 16) {
        AES_decrypt((const unsigned char *)_message + i, output + i, &decrypt_key);
    }

    return (char *)output;
}

// encrypt _message of size _message_len using AES cypher with 128 bit key length
char *encrypt_message(char *_message, int _message_len) {
    // setup decrytpion key
    AES_KEY encrypt_key;
    AES_set_encrypt_key((const unsigned char *)"xfindr00", KEY_LENGTH, &encrypt_key);

    unsigned char *output = (unsigned char *)calloc(_message_len, 1);

    for (int i = 0; i < _message_len; i += 16) {
        AES_encrypt((const unsigned char *)_message + i, output + i, &encrypt_key);
    }

    return (char *)output;
}

void callback_handler(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // initialize variable for output print
    stringstream ss;

    const u_char *packet_totlen = packet + ETH_HLEN;
    ether_header *eth_header = (ether_header *)packet;
    u_short ethertype = ntohs(eth_header->ether_type);

    int packet_id = 0;
    int file_name_len = 0;
    string packet_data;

    int ll;

    // process ether type
    switch (ethertype) {
        // process IPv4 packet
        case ETHERTYPE_IP: {
            // get packet header
            const struct iphdr *ip_header =
                (struct iphdr *)(packet + sizeof(struct ethhdr));
            ll = ip_header->ihl << 2;

            const struct icmphdr *icmp_header =
                (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

            if (DEBUG) {
                cout << "file name length is: " << icmp_header->un.echo.sequence << endl
                     << endl;
            }
            packet_id = icmp_header->un.echo.id;
            file_name_len = icmp_header->un.echo.sequence;

            switch (ip_header->protocol) {
                case IPPROTO_ICMP: {
                    if ((packet_id & 0x0fff) != ICMP_PACKET_ID) {
                        break;
                    }
                    // print length of recieved packet
                    cout << " length " << pkthdr->len << " bytes" << endl;

                    u_int icmpDataLength = pkthdr->caplen - (ETH_HLEN + (ip_header->ihl * 4) + sizeof(struct icmphdr));
                    unsigned char *tmpp;
                    tmpp = (unsigned char *)decrypt_message((char *)packet + ETH_HLEN + ll + sizeof(struct icmphdr), icmpDataLength);

                    cout << "packet id: " << packet_id << endl;
                    cout << "packet data size: " << packet_data.length() << endl;
                    packet_id = packet_id >> 12;
                    cout << "id is: " << packet_id << endl;
                    //printf("%s\n", tmpp);

                    string file_name_tmp((char *)tmpp);
                    file_name_tmp = file_name_tmp.substr(0, file_name_len);

                    if (1) {
                        cout << "file name: " << file_name_tmp << endl;
                    }

                    ofstream outfile;
                    outfile.open(file_name_tmp.append(".out"), std::ios_base::app);  // append instead of overwrite
                    outfile << string((char *)tmpp + file_name_len, icmpDataLength - file_name_len - packet_id);
                    outfile.close();

                    break;
                }
                default:
                    // filter removes other types
                    break;
            }
            break;
        }
        case ETHERTYPE_IPV6: {
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETH_HLEN);
            auto protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            switch (protocol) {
                case IPPROTO_ICMPV6: {
                    struct icmp6_hdr *icmp_header = (struct icmp6_hdr *)(packet + ETH_HLEN + 40);
                    cout << " length " << pkthdr->len << " bytes" << endl;
                    u_int icmpDataLength = pkthdr->caplen - (ETH_HLEN + 40 + sizeof(struct icmphdr));
                    file_name_len = icmp_header->icmp6_dataun.icmp6_un_data16[1];

                    if ((icmp_header->icmp6_dataun.icmp6_un_data16[0] & 0x0fff) != ICMP_PACKET_ID) {
                        break;
                    }

                    unsigned char *tmpp;
                    tmpp = (unsigned char *)decrypt_message((char *)packet + ETH_HLEN + 40 + sizeof(struct icmphdr), icmpDataLength);
                    packet_id = ((icmp_header->icmp6_dataun.icmp6_un_data16[0]) >> 12);
                    cout << "packet id: " << packet_id << endl;
                    cout << "packet data size: " << icmpDataLength << endl;
                    //printf("%s\n", tmpp);

                    string file_name_tmp((char *)tmpp);
                    file_name_tmp = file_name_tmp.substr(0, file_name_len);

                    ofstream outfile;
                    outfile.open(file_name_tmp.append(".out"), std::ios_base::app);  // append instead of overwrite
                    outfile << string((char *)tmpp + file_name_len, icmpDataLength - file_name_len - packet_id);
                    outfile.close();

                    break;
                }
                default: {
                    break;
                }
            }
            break;
        }
    }
}

// return struct with IPv4 or IPv6 address stats
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
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

int send_custom_icmp_packet(addrinfo *_server_info, char *_file_data, int _file_data_len, int _file_data_len_original, bool ipv6, int _sock, int _name_len) {
    char padding = (AES_BLOCK_SIZE - _file_data_len_original % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;

    // create and intialize ICMP packet header
    struct icmp icmp_hdr;
    icmp_hdr.icmp_cksum = 0;
    icmp_hdr.icmp_id = ((0x000 | padding) << 12) | ICMP_PACKET_ID;
    icmp_hdr.icmp_seq = _name_len;
    if (ipv6)
        icmp_hdr.icmp_type = ICMP6_ECHO_REQUEST;
    else
        icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;

    char *tmpp;
    tmpp = decrypt_message(_file_data, _file_data_len);
    printf("%s\n", tmpp);

    cout << "original file data len: " << _file_data_len_original << endl;
    cout << "padded original len: " << _file_data_len_original + padding << endl;
    cout << "padding: " << (int)padding << endl;
    // concat data to ICMP header
    u_int8_t icmpBuffer[1500];
    u_int8_t *icmpData = icmpBuffer + 8;

    // set ICMP header and set data after header
    memcpy(icmpBuffer, &icmp_hdr, 8);
    memcpy(icmpData, _file_data, _file_data_len + padding);

    // calculate new checksum with appended data and set new header
    icmp_hdr.icmp_cksum = icmp_cksum((uint16_t *)icmpBuffer, 8 + _file_data_len);
    memcpy(icmpBuffer, &icmp_hdr, 8);

    // send ICMP ECHO packet to selected ip address
    if (sendto(_sock, icmpBuffer, 8 + _file_data_len, 0, (struct sockaddr *)(_server_info->ai_addr), _server_info->ai_addrlen) <= 0) {
        cerr << "ERROR - Failed to send packet: " << strerror(errno) << endl;
        return false;
    }

    if (DEBUG)
        cout << "Successfully sent echo request" << endl;

    return 0;
}

int main(int argc, char **argv) {
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
                return EXIT_FAILURE;
        }
    }

    // check if application runs in listen (-l) mode
    if (L_opt) {
        cout << "Listen mode" << endl;

        char errbuf[PCAP_ERRBUF_SIZE];

        // get network interface address and mask
        pcap_t *handler;
        struct bpf_program fp;
        string interface = "enp0s3";
        bpf_u_int32 maskp;
        bpf_u_int32 netp;

        pcap_lookupnet(interface.c_str(), &netp, &maskp, errbuf);

        // open device for reading
        handler = pcap_open_live(interface.c_str(), BUFSIZ, 1, -1, errbuf);
        if (handler == NULL) {
            cerr << "ERROR - pcap_open_live(): " << errbuf;
            return EXIT_FAILURE;
        }

        // filter compilation
        if (pcap_compile(handler, &fp, FILTER_STRING, 0, netp) == -1) {
            cerr << "ERROR - In function pcap_compile";
            return EXIT_FAILURE;
        }

        // set filter
        if (pcap_setfilter(handler, &fp) == -1) {
            cerr << "ERROR - setting filter";
            return EXIT_FAILURE;
        }

        // loop callback function
        pcap_loop(handler, 0, callback_handler, NULL);

        // memory cleanup
        pcap_freecode(&fp);
        pcap_close(handler);
        cout << endl;

        return 0;
    } else {
        // check arguments in sender mode
        if (R_opt.empty()) {
            cerr << "ERROR - Missing file name!" << endl;
            return EXIT_FAILURE;
        } else if (S_opt.empty()) {
            cerr << "ERROR - Missing IP address or hostname!" << endl;
            return EXIT_FAILURE;
        }

        // read file into buffer
        ifstream f(R_opt.c_str());
        stringstream file_data;
        int file_data_len;

        if (f.good()) {
            if (DEBUG)
                cout << "File exists" << endl;
            file_data << f.rdbuf();
            file_data_len = file_data.tellp();
            if (DEBUG)
                cout << "File data length: " << file_data_len << endl;
        } else {
            cerr << "ERROR - File not found" << endl;
            return EXIT_FAILURE;
        }
        f.close();

        // set sender and reciever info
        struct addrinfo hints, *server_info;
        int status, protocol;
        char ip_string[INET6_ADDRSTRLEN];
        bool ipv6_packet = false;

        memset(&hints, 0, sizeof(hints));
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
        else {
            protocol = IPPROTO_ICMPV6;
            ipv6_packet = true;
        }

        // create socket
        int sock;
        if (protocol == IPPROTO_ICMPV6 or protocol == IPPROTO_ICMP) {
            if ((sock = socket(server_info->ai_family, SOCK_RAW, protocol)) < 0) {
                cerr << "ERROR - Failed creating socket: " << gai_strerror(status) << endl;
                return EXIT_FAILURE;
            }
        } else {
            cerr << "ERROR - Incorrect protocol!" << endl;
            return EXIT_FAILURE;
        }

        if (protocol != IPPROTO_ICMPV6) {
            uint8_t ttl = 255;
            if (setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
                cerr << "ERROR - Failed to set TTL option" << endl;
                return EXIT_FAILURE;
            }
        }

        if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
            cerr << "ERROR - Failed to set non-blocking" << endl;
            return EXIT_FAILURE;
        }

        // send file data
        int tmp_size = 1392 - R_opt.length() - 1;

        cout << "<==== starting sending data ====>" << endl
             << endl;

        while (file_data_len >= 0) {
            char prepared_data[1392];
            memset(prepared_data, 0, 1392);
            memcpy(prepared_data, R_opt.c_str(), R_opt.length());
            file_data.read(prepared_data + R_opt.length(), 1392 - R_opt.length());

            if ((1392 - R_opt.length() + 1) < file_data_len) {
                if (send_custom_icmp_packet(server_info, encrypt_message(prepared_data, 1392), 1392, 1392, ipv6_packet, sock, R_opt.length())) {
                    cerr << "failed" << endl;
                }
                file_data_len -= (1392 - R_opt.length());
                cout << "<==========> greater" << endl;

            } else {
                int tmp_file_data_len = (file_data_len + R_opt.length());

                int padded_prepared_data_size = tmp_file_data_len + (AES_BLOCK_SIZE - tmp_file_data_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
                cout << padded_prepared_data_size << endl;

                if (send_custom_icmp_packet(server_info, encrypt_message(prepared_data, padded_prepared_data_size), padded_prepared_data_size, tmp_file_data_len, ipv6_packet, sock, R_opt.length())) {
                    cerr << "failed" << endl;
                }
                cout << "<==========>" << endl
                     << endl;

                file_data_len -= 1392;
            }
        }

        if (DEBUG) {
            cout << "R_opt = " << R_opt << endl;
            cout << "S_opt = " << S_opt << endl;
            cout << "L_opt = " << L_opt << endl;
        }
        close(sock);
    }

    return EXIT_SUCCESS;
}

// ahoj ahooj ahoooooooooooooooo
// ahoj ahooj ahoooj