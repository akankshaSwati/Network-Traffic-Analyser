#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h> 
#include <pcap.h>

using namespace std;

void process_packet(const struct pcap_pkthdr* header, const u_char* packet_data) {
    // You can process or print the packet data here
    printf("Packet Length: %d\n", header->len);

    // Print the packet data as hexadecimal bytes
    for (int i = 0; i < header->len; i++) {
        printf("%02X ", packet_data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); // Newline after every 16 bytes
        }
    }
    printf("\n");
    printf("\n");
}

void extract_ip_info(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip* ip_header;
    struct ip6_hdr* ip6_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct icmphdr* icmp_header;

    // Extract the IP header from the packet
    ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)

    // Determine the IP version (IPv4 or IPv6)
    if (ip_header->ip_v == 4) {
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
        
        // Determine the protocol
        int protocol = ip_header->ip_p;
        std::string protocol_name;
        int source_port = 0, dest_port = 0;

        if (protocol == IPPROTO_TCP) {
            tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header
            source_port = ntohs(tcp_header->th_sport);
            dest_port = ntohs(tcp_header->th_dport);
            protocol_name = "TCP";
        } else if (protocol == IPPROTO_UDP) {
            udp_header = (struct udphdr*)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header
            source_port = ntohs(udp_header->uh_sport);
            dest_port = ntohs(udp_header->uh_dport);
            protocol_name = "UDP";
        } else if (protocol == IPPROTO_ICMP) {
            icmp_header = (struct icmphdr*)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header
            protocol_name = "ICMP";
        } else {
            protocol_name = "Unknown";
        }

        // Print the extracted information
        cout << "IPv4 Packet:" << endl;
        cout << "Source IP: " << source_ip << endl;
        cout << "Destination IP: " << dest_ip << endl;
        cout << "Protocol: " << protocol_name << endl;
        if(source_port!=0) cout << "Source Port: " << source_port << endl;
        if(dest_port!=0) cout << "Destination Port: " << dest_port << endl;

    } else if (ip_header->ip_v == 6) {
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
        
        // Determine the protocol
        int protocol = ip_header->ip_p;
        string protocol_name;
        int source_port = 0, dest_port = 0;

        if (protocol == IPPROTO_TCP) {
            tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header
            source_port = ntohs(tcp_header->th_sport);
            dest_port = ntohs(tcp_header->th_dport);
            protocol_name = "TCP";
        } else if (protocol == IPPROTO_UDP) {
            udp_header = (struct udphdr*)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header
            source_port = ntohs(udp_header->uh_sport);
            dest_port = ntohs(udp_header->uh_dport);
            protocol_name = "UDP";
        } else if (protocol == IPPROTO_ICMP) {
            icmp_header = (struct icmphdr*)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header
            protocol_name = "ICMP";
        } else {
            protocol_name = "Unknown";
        }

        // Print the extracted information
        cout << "IPv6 Packet:" << endl;
        cout << "Source IP: " << source_ip << endl;
        cout << "Destination IP: " << dest_ip << endl;
        cout << "Protocol: " << protocol_name << endl;
        if(source_port!=0) cout << "Source Port: " << source_port << endl;
        if(dest_port!=0) cout << "Destination Port: " << dest_port << endl;
    }
    cout<<endl;
}

bool pcap_analyser_tcp(const char* pcap_file, bool show_packet_data){
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        
        if (returnValue == 1) {
            cout<<"----------------------------------------------------------------------------";
            cout<<"TCP PACKET:"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------";
            // Process packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {

            // Timeout elapsed 
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }
    pcap_close(handle);
    return 1;
}

bool pcap_analyser_udp(const char* pcap_file, bool show_packet_data){
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "udp port 53";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        
        if (returnValue == 1) {
            cout<<"----------------------------------------------------------------------------";
            cout<<"UDP PACKET:"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------";
            // Process packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {

            // Timeout elapsed 
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }
    pcap_close(handle);
    return 1;
}

bool pcap_analyser_ipv4(const char* pcap_file, bool show_packet_data) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return false; // Change return type to bool and return false on error
    }

    struct bpf_program fp;
    char filter_exp[] = "ip"; // Filter expression to capture only IPv4 packets

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false; // Return false on error
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false; // Return false on error
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        if (returnValue == 1) {
            cout<<"----------------------------------------------------------------------------";
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------";
            // Process IPv4 packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {
            // Timeout elapsed 
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }

    pcap_close(handle);
    return true; // Return true on success
}

bool pcap_analyser_ipv6(const char* pcap_file, bool show_packet_data) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return false; // Change return type to bool and return false on error
    }

    struct bpf_program fp;
    char filter_exp[] = "ip6"; // Filter expression to capture only IPv6 packets

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false; // Return false on error
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false; // Return false on error
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        if (returnValue == 1) {
            cout<<"----------------------------------------------------------------------------";
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------";
            // Process IPv6 packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {
            // Timeout elapsed 
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }

    pcap_close(handle);
    return true; // Return true on success
}

bool pcap_analyser_udp_icmp(const char* pcap_file, bool show_packet_data) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return false; // Change return type to bool and return false on error
    }

    struct bpf_program fp;
    char filter_exp[] = "udp port 53 or icmp"; // Change filter expression to capture UDP packets on port 53 and ICMP packets

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false; // Return false on error
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false; // Return false on error
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        if (returnValue == 1) {
            if (header->len > 14) { // Skip Ethernet frames (14 bytes) to process IP packets
                if (packet[12] == 0x08 && packet[13] == 0x00) {
                    cout<<"----------------------------------------------------------------------------";
                    cout<<"ICMP PACKET:"<<endl;
                    extract_ip_info(header, packet);
                    if(show_packet_data) process_packet(header,packet);
                    cout<<"----------------------------------------------------------------------------";
                    // Process IP packets here
                    // 'header' contains packet metadata, and 'packet' contains packet data
                }
            }
        } else if (returnValue == 0) {
            // Timeout elapsed 
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }

    pcap_close(handle);
    return true; // Return true on success
}

void filter_packets_by_source_ip(const char* pcap_file, const char* source_ip, bool show_packet_data) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct bpf_program fp;

    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "src host %s", source_ip);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        if (returnValue == 1) {
            cout<<"----------------------------------------------------------------------------";
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------";
        } else if (returnValue == 0) {
            // Timeout elapsed
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }
    pcap_close(handle);
}

void filter_packets_by_dest_ip(const char* pcap_file, const char* dest_ip, bool show_packet_data) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct bpf_program fp;

    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "dst host %s", dest_ip);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (int returnValue = pcap_next_ex(handle, &header, &packet)) {
        if (returnValue == 1) {
            cout << "----------------------------------------------------------------------------" << endl;
            extract_ip_info(header, packet);
            if (show_packet_data) process_packet(header, packet);
            cout << "----------------------------------------------------------------------------" << endl;
        } else if (returnValue == 0) {
            // Timeout elapsed 
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            break;
        }
    }
    pcap_close(handle);
}

int main() {
    const char* pcap_file = "wire.pcap";
    const char* source_ip = "142.250.82.148";
    const char* dest_ip = "142.250.82.148";
    bool show_packet_data = 0;
    filter_packets_by_dest_ip(pcap_file, dest_ip, show_packet_data);
    return 0;
}