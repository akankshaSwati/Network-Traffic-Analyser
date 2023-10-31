#include <cstring>
#include <iostream>
#include <netinet/ip.h>
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

    // Extract the IP header from the packet
    ip_header = (struct ip*)(packet + 14); // Skip Ethernet header (14 bytes)

    // Convert the source and destination IP addresses to human-readable format
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Use inet_ntoa for IPv4 addresses
    strcpy(source_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dest_ip, inet_ntoa(ip_header->ip_dst));

    // Print the extracted IP information
    std::cout << "Source IP: " << source_ip << std::endl;
    std::cout << "Destination IP: " << dest_ip << std::endl;
    printf("\n");
}

bool pcap_analyser_tcp(){
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline("wire.pcap", errbuf);
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
            cout<<"TCP PACKET:"<<endl;
            process_packet(header, packet);
            extract_ip_info(header, packet);
            // Process packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {

            // Timeout elapsed (if required)
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

bool pcap_analyser_udp(){
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline("wire.pcap", errbuf);
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
            cout<<"UDP PACKET:"<<endl;
            process_packet(header, packet);
            extract_ip_info(header, packet);
            // Process packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {

            // Timeout elapsed (if required)
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

bool pcap_analyser_ipv4() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline("wire.pcap", errbuf);
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
            cout << "IPv4 PACKET:" << endl;
            process_packet(header, packet);
            extract_ip_info(header, packet);
            // Process IPv4 packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {
            // Timeout elapsed (if required)
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

bool pcap_analyser_ipv6() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline("wire.pcap", errbuf);
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
            cout << "IPv6 PACKET:" << endl;
            process_packet(header, packet);
            extract_ip_info(header, packet);
            // Process IPv6 packet here
            // 'header' contains packet metadata, and 'packet' contains packet data
        } else if (returnValue == 0) {
            // Timeout elapsed (if required)
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

bool pcap_analyser_udp_icmp() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline("wire.pcap", errbuf);
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
                    cout<<"ICMP PACKET:"<<endl;
                    process_packet(header, packet);
                    extract_ip_info(header, packet);
                    // Process IP packets here
                    // 'header' contains packet metadata, and 'packet' contains packet data
                }
            }
        } else if (returnValue == 0) {
            // Timeout elapsed (if required)
        } else if (returnValue == -1) {
            fprintf(stderr, "Error reading the next packet: %s\n", pcap_geterr(handle));
            break;
        } else if (returnValue == -2) {
            // End of file reached
            // process_packet(header, packet); // Assuming this function processes packets
            break;
        }
    }

    pcap_close(handle);
    return true; // Return true on success
}

int main(){
    // pcap_analyser_tcp();
    // pcap_analyser_udp();
    // pcap_analyser_udp_icmp();
    // pcap_analyser_ipv4();
    // pcap_analyser_ipv6();


}