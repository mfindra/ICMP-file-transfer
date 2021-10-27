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

#define PACKET_SIZE 1500
#define DEBUG 1

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

    // ipv6
    string ip6_dest_addr;
    string ip6_src_addr;

    const u_char *packet_totlen = packet + ETH_HLEN;
    ether_header *eth_header = (ether_header *)packet;
    u_short ethertype = htons(eth_header->ether_type);

    int packet_id = 0;
    int file_name_len = 0;
    string packet_data;

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

            const struct icmphdr *icmp_header =
                (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

            if (DEBUG) {
                cout << "id is: " << icmp_header->un.echo.id << endl;
                cout << "file name length is: " << icmp_header->un.echo.sequence << endl
                     << endl;
            }
            packet_id = icmp_header->un.echo.id;
            file_name_len = icmp_header->un.echo.sequence;

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
    if (ip_src_tmp != "") cout << " : " << ip_src_tmp;

    // print destination ip address and port
    if (ip6_dest_addr != "")
        cout << " > " << ip6_dest_addr;
    else
        cout << " > " << inet_ntoa(addr_dest_tmp);
    if (ip_dest_tmp != "") cout << " : " << ip_dest_tmp;

    // print length of recieved packet
    cout << " length " << pkthdr->len << " bytes" << endl;

    for (int i = 42; i < pkthdr->caplen; i++) {
        /* Check if the packet data is printable */
        // printf("%c", packet[i]); /* Print it */
        packet_data.push_back(packet[i]);
    }

    string file_name_tmp = packet_data.substr(0, file_name_len);

    if (packet_id == 69) {
        ofstream outfile(packet_data.append(".out"));
        outfile.close();
    } else if (packet_id = 71) {
        ofstream outfile;
        outfile.open(file_name_tmp.append(".out"), std::ios_base::app);  // append instead of overwrite
        outfile << packet_data.substr(file_name_len, packet_data.length());
        outfile.close();
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

unsigned char *encrypt_message(string _message, int _message_len) {
    AES_KEY encrypt_key;
    AES_set_encrypt_key((const unsigned char *)"xfindr00", 128, &encrypt_key);

    unsigned char *output = (unsigned char *)calloc(_message_len + (AES_BLOCK_SIZE % _message_len), 1);

    AES_encrypt((unsigned char *)_message.c_str(), output, &encrypt_key);

    cout << "string has been encrypted" << endl;

    return output;
}

char *decrypt_message(unsigned char *_message) {
    AES_KEY decrypt_key;
    AES_set_decrypt_key((unsigned char *)"xfindr00", 128, &decrypt_key);
    AES_decrypt((unsigned char *)_message, (unsigned char *)_message, &decrypt_key);

    printf("decrypted string: %s\n", _message);
    return (char *)_message;
}

int send_custom_icmp_packet(addrinfo *_server_info, char *_file_data, int _file_data_len, int _sock, int _id, int _name_len) {
    // create and intialize ICMP packet header
    struct icmp icmp_hdr;
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_cksum = 0;
    icmp_hdr.icmp_id = _id;
    icmp_hdr.icmp_seq = _name_len;

    // concat data to ICMP header
    u_int8_t icmpBuffer[1500];
    u_int8_t *icmpData = icmpBuffer + 8;

    // set ICMP header and set data after header
    memcpy(icmpBuffer, &icmp_hdr, 8);
    memcpy(icmpData, _file_data, _file_data_len);

    // calculate new checksum with appended data and set new header
    icmp_hdr.icmp_cksum = icmp_cksum((uint16_t *)icmpBuffer, 8 + _file_data_len);
    memcpy(icmpBuffer, &icmp_hdr, 8);

    // send ICMP ECHO packet to selected ip address
    if (sendto(_sock, icmpBuffer, 8 + _file_data_len, 0, (struct sockaddr *)(_server_info->ai_addr), _server_info->ai_addrlen) <= 0) {
        cerr << "Failed to send packet: " << strerror(errno) << endl;
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

        string filter_string = "icmp[icmptype] == icmp-echo";

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
        pcap_loop(handler, 0, callback_handler, NULL);

        // memory cleanup
        pcap_freecode(&fp);
        pcap_close(handler);
        cout << endl;

        return 0;
    } else {
        // check arguments in sender mode
        if (R_opt.empty()) {
            fprintf(stderr, "ERROR - Missing file name!\n");
            return EXIT_FAILURE;
        } else if (S_opt.empty()) {
            fprintf(stderr, "ERROR - Missing IP address or hostname!\n");
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
                cout << file_data_len << endl;
        } else {
            fprintf(stderr, "ERROR - File not found\n");
            return EXIT_FAILURE;
        }
        f.close();

        // set sender and reciever info
        struct addrinfo hints, *server_info;
        int status, protocol;
        char ip_string[INET6_ADDRSTRLEN];

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
        else
            protocol = IPPROTO_ICMPV6;

        // create socket
        int sock;
        if ((sock = socket(server_info->ai_family, SOCK_RAW, protocol)) < 0) {
            fprintf(stderr, "Error creating socket:  %s\n", gai_strerror(status));
            return 1;
        }

        uint8_t ttl = 255;
        if (setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
            cerr << "Failed to set TTL option" << endl;
            return false;
        }

        if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
            cerr << "Failed to set non-blocking" << endl;
            return false;
        }

        stringstream encrypteddd;
        stringstream decrypteddd;
        int counter = 0;

        while (counter * 16 < file_data.str().length()) {
            unsigned char *file_data_encrypted;
            file_data_encrypted = encrypt_message(file_data.str().substr(counter * 16, 16), (file_data.str().substr(counter * 16, 16)).length());
            encrypteddd << file_data_encrypted;
            decrypt_message(file_data_encrypted);
            counter++;
        }
        counter = 0;

        while (counter * 16 < encrypteddd.str().length()) {
            string tp = encrypteddd.str().substr(counter * 16, 16);
            unsigned char *val = new unsigned char[tp.length() + 1];
            strcpy((char *)val, tp.c_str());
            cout << decrypt_message(val) << endl;
            counter++;
        }

        // send file name
        if (send_custom_icmp_packet(server_info, (char *)R_opt.c_str(), R_opt.length(), sock, 69, 0)) {
            cerr << "failed" << endl;
        }

        /*
        // send packet data
        if (file_data.str().length() > 1500) {
            if (DEBUG) {
                cout << "File size greater than one packet" << endl;
                cout << file_data.str().length() << endl;
            }
            int tmp_size = 1000;
            int tmp_start = 0;
            int data_len = file_data.str().length();
            while (tmp_start < data_len) {
                if ((tmp_start + 1000) > data_len) {
                    tmp_size = data_len - tmp_start;
                    cout << "start: " << tmp_start << endl
                         << "size: " << tmp_size << endl
                         << endl;
                    string tmp = R_opt + file_data.str().substr(tmp_start, tmp_size);
                    if (send_custom_icmp_packet(server_info, (char *)tmp.c_str(), tmp.length(), sock, 71, R_opt.length())) {
                        cerr << "failed" << endl;
                    }
                    break;
                } else {
                    cout << "start: " << tmp_start << endl
                         << "size: " << tmp_size << endl
                         << endl;
                    string tmp = R_opt + file_data.str().substr(tmp_start, tmp_size);
                    if (send_custom_icmp_packet(server_info, (char *)tmp.c_str(), tmp.length(), sock, 71, R_opt.length())) {
                        cerr << "failed" << endl;
                    }
                    tmp_start += tmp_size;
                }
            }
        } else {
            if (send_custom_icmp_packet(server_info, (char *)file_data.str().c_str(), file_data_len, sock, 71, R_opt.length())) {
                cerr << "failed" << endl;
            }
        }*/

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