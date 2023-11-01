#include <cstring>
#include <ctime>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h> 
#include <pcap.h>

using namespace std;

void print_packet_timestamp(const struct pcap_pkthdr* header) {
    time_t timestamp = header->ts.tv_sec;
    struct tm timeinfo;

    if (localtime_r(&timestamp, &timeinfo)) {
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
        printf("Timestamp: %s.%06ld\n", time_str, header->ts.tv_usec);
    } else {
        printf("Error converting timestamp to human-readable format\n");
    }
}

void process_packet(const struct pcap_pkthdr* header, const u_char* packet_data) {
    // Print the packet length in bytes
    printf("Packet Cap Length: %u bytes\n", header->caplen);
    printf("Packet Length: %u bytes\n", header->len);
    print_packet_timestamp(header);
    printf("\n");
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
            cout<<"----------------------------------------------------------------------------"<<endl;
            cout<<"TCP PACKET:"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------"<<endl;
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
            cout<<"----------------------------------------------------------------------------"<<endl;
            cout<<"UDP PACKET:"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------"<<endl;
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
            cout<<"----------------------------------------------------------------------------"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------"<<endl;
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
            cout<<"----------------------------------------------------------------------------"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------"<<endl;
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
                    cout<<"----------------------------------------------------------------------------"<<endl;
                    cout<<"ICMP PACKET:"<<endl;
                    extract_ip_info(header, packet);
                    if(show_packet_data) process_packet(header,packet);
                    cout<<"----------------------------------------------------------------------------"<<endl;
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
            cout<<"----------------------------------------------------------------------------"<<endl;
            extract_ip_info(header, packet);
            if(show_packet_data) process_packet(header,packet);
            cout<<"----------------------------------------------------------------------------"<<endl;
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

void filter_packets_by_source_and_dest_ip(const char* pcap_file, const char* source_ip, const char* dest_ip, bool show_packet_data) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct bpf_program fp;

    // Construct the filter expression to capture packets with the specified source and destination IP
    char filter_exp[400]; // Adjust the size as needed
    snprintf(filter_exp, sizeof(filter_exp), "src host %s and dst host %s", source_ip, dest_ip);

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
}

int main() {
    string s;
    cout<<"Enter the name with extension of the .pcap file you want to analyze."<<endl;
    cin>>s;
    cout<<"Analyzing "<<s<< "........"<<endl;
    const char* pcap_file = s.c_str();

    while(1){
        cout<<"Do you want to filter packets based on Protocols or IP addresses?\nEnter p or P for protocol\nEnter i or I for IP address"<<endl;
        char c; cin>>c;
    
        if(c=='p'||c=='P'){
            cout<<"Choose a protocol among the given to filter packets: "<<endl;
            cout<<"Type the index no. for using the corresponding protocol filter:"<<endl;
            cout<<"1 - tcp\n2 - udp\n3 - icmp\n4 - ipv4\n5 - ipv6"<<endl;
            int n;
            cin>>n;
            cout<<"Do you want to print Packet data? Print y / Y for YES and n / N / (any other value) for NO !"<<endl;
            bool show_packet_data = 0;
            char b; cin>>b;
            if(b=='y'||b=='Y') show_packet_data = 1;
            
            if(n==1) pcap_analyser_tcp(pcap_file , show_packet_data);
            else if(n==2) pcap_analyser_udp(pcap_file , show_packet_data);
            else if(n==3) pcap_analyser_udp_icmp(pcap_file , show_packet_data);
            else if(n==4) pcap_analyser_ipv4(pcap_file , show_packet_data);
            else if(n==5) pcap_analyser_ipv6(pcap_file , show_packet_data);
            else {
                cout<<"Invalid Input!!! Try Again!!!"<<endl;
                continue;
            }

            break;
        }
        else if(c=='i'||c=='I'){
            cout<<"Do you want to filter by:\n1 - Source IP\n2 - Destination IP\n3 - Both?\nEnter the Index no.: "<<endl;
            int n; cin>>n;
            cout<<"Do you want to print Packet data? Print y / Y for YES and n / N / (any other value) for NO !"<<endl;
            bool show_packet_data = 0;
            char b; cin>>b;
            if(b=='y'||b=='Y') show_packet_data = 1;
            if(n==1){
                string source;
                cout<<"Enter Source IP:"<<endl;
                cin>>source;
                filter_packets_by_source_ip(pcap_file, source.c_str(),show_packet_data);
            }
            else if(n==2){
                string dest;
                cout<<"Enter Destination IP:"<<endl;
                cin>>dest;
                filter_packets_by_dest_ip(pcap_file, dest.c_str(),show_packet_data);
            }
            else if(n==3){
                string source,dest;
                cout<<"Enter Source IP:"<<endl;
                cin>>source;
                cout<<"Enter Destination IP:"<<endl;
                cin>>dest;
                filter_packets_by_source_and_dest_ip(pcap_file, source.c_str(),dest.c_str(),show_packet_data);
            }
            else{
                cout<<"Invalid Input!!! Try Again!!!"<<endl;
                continue;
            }
            break;
        }
        cout<<"Wrong Input!!! Try Again!!!";
    }
    return 0;
}