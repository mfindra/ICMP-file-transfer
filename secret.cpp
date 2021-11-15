/*
author: Michal Findra, xfindr00
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
#define DEBUG 0
#define KEY_LENGTH 128
#define PACKET_DATA_SIZE 1360
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

    // set output of decryption
    unsigned char *decryption_output = (unsigned char *)calloc(_message_len, 1);

    // decrypt data in 16B blocks
    for (int i = 0; i < _message_len; i += 16) {
        AES_decrypt((const unsigned char *)_message + i, decryption_output + i, &decrypt_key);
    }
    return (char *)decryption_output;
}

// encrypt _message of size _message_len using AES cypher with 128 bit key length
char *encrypt_message(char *_message, int _message_len) {
    // setup decrytpion key
    AES_KEY encrypt_key;
    AES_set_encrypt_key((const unsigned char *)"xfindr00", KEY_LENGTH, &encrypt_key);

    // set output of encryption
    unsigned char *encryption_output = (unsigned char *)calloc(_message_len, 1);

    // encrpyt data in 16B blocks
    for (int i = 0; i < _message_len; i += 16) {
        AES_encrypt((const unsigned char *)_message + i, encryption_output + i, &encrypt_key);
    }
    return (char *)encryption_output;
}

// handling function for capturing packets
void callback_handler(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int packet_id = 0;
    int file_name_len = 0;
    string packet_data;

    // get packet type from header
    ether_header *eth_header = (ether_header *)packet;
    u_short ethertype = ntohs(eth_header->ether_type);

    // process ether type
    switch (ethertype) {
        // process IPv4 packet
        case ETHERTYPE_IP: {
            // get packet header
            const struct iphdr *ip_header =
                (struct iphdr *)(packet + sizeof(struct ethhdr));

            // get icmpv4 header
            const struct icmphdr *icmp_header =
                (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

            // get icmp packet id (padding and identification)
            packet_id = icmp_header->un.echo.id;

            // get icmp packet sequence (file name length)
            file_name_len = icmp_header->un.echo.sequence;

            switch (ip_header->protocol) {
                case IPPROTO_ICMP: {
                    // check if packet has valid identifier (stored in bottom 3B in packet_id)
                    if ((packet_id & 0x0fff) != ICMP_PACKET_ID)
                        break;

                    // get data length from packet header
                    int icmp_data_len = pkthdr->caplen - (ETH_HLEN + (ip_header->ihl * 4) + sizeof(struct icmphdr));

                    // get and decrypt file name and packet data merged in one string
                    unsigned char *packed_data_merged;
                    packed_data_merged = (unsigned char *)decrypt_message((char *)packet + ETH_HLEN + (ip_header->ihl << 2) + sizeof(struct icmphdr), icmp_data_len);

                    // shift bytes in packet_id to get padding (stored in top 1B in packet_id)
                    packet_id = packet_id >> 12;

                    // separete file name from merged string
                    string file_name((char *)packed_data_merged);
                    file_name = file_name.substr(0, file_name_len);

                    if (DEBUG) {
                        cout << " length " << pkthdr->len << " bytes" << endl;
                        cout << "packet data size: " << packet_data.length() << endl;
                        cout << "id is: " << packet_id << endl;
                        //printf("%s\n", packed_data_merged);
                        cout << "file name: " << file_name << endl;
                    }

                    // open file for output and write data into file
                    ofstream outfile;
                    outfile.open(file_name, std::ios_base::app);  // append instead of overwrite
                    outfile << string((char *)packed_data_merged + file_name_len, icmp_data_len - file_name_len - packet_id);
                    outfile.close();

                    break;
                }
                default:
                    // filter out other types
                    break;
            }
            break;
        }
        case ETHERTYPE_IPV6: {
            // get packet header
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETH_HLEN);

            // get protocol from header for icmpv6 identifiaction
            auto protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

            switch (protocol) {
                case IPPROTO_ICMPV6: {
                    // get icmpv6 header
                    struct icmp6_hdr *icmp_header = (struct icmp6_hdr *)(packet + ETH_HLEN + 40);

                    // check if packet has valid identifier (stored in bottom 3B in packet_id)
                    if ((icmp_header->icmp6_dataun.icmp6_un_data16[0] & 0x0fff) != ICMP_PACKET_ID)
                        break;

                    // get data length from packet header
                    int icmpDataLength = pkthdr->caplen - (ETH_HLEN + 40 + sizeof(struct icmphdr));

                    // get file name length from icmp packet sequence
                    file_name_len = icmp_header->icmp6_dataun.icmp6_un_data16[1];

                    // get and decrypt file name and packet data merged in one string
                    unsigned char *packet_data_merged;
                    packet_data_merged = (unsigned char *)decrypt_message((char *)packet + ETH_HLEN + 40 + sizeof(struct icmphdr), icmpDataLength);

                    // shift bytes in packet_id to get padding (stored in top 1B in packet_id)
                    packet_id = ((icmp_header->icmp6_dataun.icmp6_un_data16[0]) >> 12);

                    // separete file name from merged string
                    string file_name((char *)packet_data_merged);
                    file_name = file_name.substr(0, file_name_len);

                    if (DEBUG) {
                        cout << " length " << pkthdr->len << " bytes" << endl;
                        cout << "packet id: " << packet_id << endl;
                        cout << "packet data size: " << icmpDataLength << endl;
                        //printf("%s\n", packet_data_merged);
                        cout << "file name: " << file_name << endl;
                    }

                    // open file for output and write data into file
                    ofstream outfile;
                    outfile.open(file_name, std::ios_base::app);  // append instead of overwrite
                    outfile << string((char *)packet_data_merged + file_name_len, icmpDataLength - file_name_len - packet_id);
                    outfile.close();

                    break;
                }
                default: {
                    // filter out other types
                    break;
                }
            }
            break;
        }
        default: {
            // filter out other types
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

// calculate packet checksum
u_int16_t icmp_packet_checksum(uint16_t *buffer, int length) {
    uint32_t sum = 0;
    uint16_t *buf = buffer;
    uint16_t answer = 0;

    // sum up all 16 bits in sum
    for (answer = 0; length > 1; length -= 2) {
        sum += *buf;
        buf++;
    }

    // even length - add last byte
    if (length == 1) {
        sum += *(uint16_t *)buf;
    }

    // one complement of result
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

// create icmp packet and send it using socket
int send_custom_icmp_packet(addrinfo *_server_info, char *_file_data, int _file_data_len, int _file_data_len_original, bool ipv6, int _sock, int _name_len) {
    // calculate padding needed for data to be in 16B blocks
    char padding = _file_data_len - _file_data_len_original;

    // create and intialize ICMP packet header
    struct icmp icmp_hdr;
    icmp_hdr.icmp_cksum = 0;
    icmp_hdr.icmp_code = 0;

    // store file name length in icmp packet sequence
    icmp_hdr.icmp_seq = _name_len;

    // store identification in bottom 3B and padding in top 1B in icmp packet ID
    icmp_hdr.icmp_id = ((0x0000 | padding) << 12) | ICMP_PACKET_ID;

    // set icmp packet type (ipv4 or ipv6)
    if (ipv6)
        icmp_hdr.icmp_type = ICMP6_ECHO_REQUEST;
    else
        icmp_hdr.icmp_type = ICMP_ECHO;

    if (DEBUG) {
        cout << "original file data len: " << _file_data_len_original << endl;
        cout << "padded original len: " << _file_data_len_original + padding << endl;
        cout << "padding: " << (unsigned int)padding << endl;
    }

    // concat data after ICMP header
    u_int8_t icmp_file_data_buffer[1500];
    u_int8_t *icmp_bytes_data = icmp_file_data_buffer + 8;

    // set ICMP header and set data after header
    memcpy(icmp_file_data_buffer, &icmp_hdr, 8);
    memcpy(icmp_bytes_data, _file_data, _file_data_len + (unsigned int)padding);

    // calculate new checksum with appended data and set new header
    icmp_hdr.icmp_cksum = icmp_packet_checksum((uint16_t *)icmp_file_data_buffer, 8 + _file_data_len);
    memcpy(icmp_file_data_buffer, &icmp_hdr, 8);

    // send ICMP ECHO packet to selected ip address
    if (sendto(_sock, icmp_file_data_buffer, 8 + _file_data_len, 0, (struct sockaddr *)(_server_info->ai_addr), _server_info->ai_addrlen) <= 0) {
        cerr << "ERROR - Failed to send packet: " << strerror(errno) << endl;
        return false;
    }

    if (DEBUG)
        cout << "Successfully sent echo request" << endl;

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    string R_opt;
    string S_opt;
    bool L_opt = false;
    int opt;

    // read and parse program arguments
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
                return EXIT_SUCCESS;
                break;
            default:
                cerr << "ERROR - Wrong argument!" << endl;
                return EXIT_FAILURE;
        }
    }

    // check if application runs in listener (-l) mode
    if (L_opt) {
        if (DEBUG) {
            cout << "Listen mode" << endl;
        }

        // intitialize buffer for error message
        char errbuf[PCAP_ERRBUF_SIZE];

        // get and set network interface address and mask
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

        return EXIT_SUCCESS;
    } else {
        // check arguments in server(sending) mode
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

        // check if file exists and read fiel data into buffer
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

        // get info
        if ((status = getaddrinfo(S_opt.c_str(), NULL, &hints, &server_info)) != 0) {
            cout << "ERROR - " << gai_strerror(status) << endl;
            return EXIT_FAILURE;
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

        // set socket options
        if (protocol != IPPROTO_ICMPV6) {
            uint8_t ttl = 255;
            if (setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
                cerr << "ERROR - Failed to set TTL option" << endl;
                return EXIT_FAILURE;
            }
        }

        // set non-blocking
        if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
            cerr << "ERROR - Failed to set non-blocking" << endl;
            return EXIT_FAILURE;
        }

        // remove file path becouse it can cause overflow
        int file_name_start = R_opt.find_last_of("\\/");
        R_opt = R_opt.substr(file_name_start + 1, R_opt.length());

        // send file data
        int tmp_size = 1392 - R_opt.length() - 1;

        if (DEBUG) {
            cout << "<==== starting sending data ====>" << endl;
        }

        // send data in block of size divisible by 16
        while (file_data_len >= 0) {
            char prepared_data[PACKET_DATA_SIZE];
            memset(prepared_data, 0, PACKET_DATA_SIZE);
            memcpy(prepared_data, R_opt.c_str(), R_opt.length());
            file_data.read(prepared_data + R_opt.length(), PACKET_DATA_SIZE - R_opt.length());

            // send packet of full packet data size
            if ((PACKET_DATA_SIZE - R_opt.length() + 1) < file_data_len) {
                if (send_custom_icmp_packet(server_info, encrypt_message(prepared_data, PACKET_DATA_SIZE), PACKET_DATA_SIZE, PACKET_DATA_SIZE, ipv6_packet, sock, R_opt.length())) {
                    cerr << "failed" << endl;
                }
                file_data_len -= (PACKET_DATA_SIZE - R_opt.length());

            } else {  // send packet of remaining size
                int tmp_file_data_len = (file_data_len + R_opt.length());
                int padded_prepared_data_size = tmp_file_data_len + (AES_BLOCK_SIZE - tmp_file_data_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
                cout << padded_prepared_data_size << endl;

                if (send_custom_icmp_packet(server_info, encrypt_message(prepared_data, padded_prepared_data_size), padded_prepared_data_size, tmp_file_data_len, ipv6_packet, sock, R_opt.length())) {
                    cerr << "failed" << endl;
                }
                cout << "<==========>" << endl
                     << endl;

                file_data_len -= PACKET_DATA_SIZE;
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