#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//strlen
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<netinet/if_ether.h>	//For ETH_P_ALL
#include<net/ethernet.h>	//For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<signal.h>
#include<iostream>
#include<string>
#include<cstdint>

bool sniffPackets = true;

void SignalHandler(int signum) {
    if (signum == SIGINT) {
        sniffPackets = false;
		printf("_______________________________________________________________________________\r\n");
        printf("Received SIGINT!!\nSniffing halted.\n");
        return;
    }
}

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	

struct FilterParams{
	std::pair<std::string,std::string> protocol;
	std::string source_ip;
	std::string destination_ip;
	int source_port;
	int destination_port;

	FilterParams()
	: protocol({"all","all"}), source_ip("any"), destination_ip("any"), source_port(0), destination_port(0)
	{}
};

void ProcessPacket(unsigned char* , int, FilterParams*);
bool print_ip_header(unsigned char* , int, FilterParams*);
void print_tcp_packet(unsigned char * , int, FilterParams*);
void print_udp_packet(unsigned char * , int, FilterParams*);
void print_icmp_packet(unsigned char* , int, FilterParams*);
void PrintData (unsigned char* , int);

void ProcessPacket(unsigned char* buffer, int size, FilterParams* f_params){

	// Extract IP Header, excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
	++total;
	switch (iph->protocol) //Check the Protocol
	{
		case 1:  //ICMP Protocol
			++icmp;
			if(f_params->protocol.second=="all" || f_params->protocol.second=="icmp")
			{
				print_icmp_packet(buffer , size, f_params);
			}
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			if(f_params->protocol.second=="all" || f_params->protocol.second=="tcp")
			{
				print_tcp_packet(buffer , size, f_params);
			}
			break;
		
		case 17: //UDP Protocol
			++udp;
			if(f_params->protocol.second=="all" || f_params->protocol.second=="udp")
			{
				print_udp_packet(buffer , size, f_params);
			}
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}

	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

bool print_ip_header(unsigned char* Buffer, int Size, FilterParams* f_params)
{ 
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	if(f_params->source_ip!="any" && f_params->source_ip!=inet_ntoa(source.sin_addr)) return false;
	if(f_params->destination_ip!="any" && f_params->destination_ip!=inet_ntoa(dest.sin_addr)) return false;

	switch (iph->protocol)
	{
		case 1:  //ICMP Protocol
			fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");
			break;
		case 2:  //IGMP Protocol
			fprintf(logfile , "\n\n***********************IGMP Packet*************************\n");
			break;
		case 6:  //TCP Protocol
			fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
			break;
		case 17: //UDP Protocol
			fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
			break;
		default: //Some Other Protocol like ARP etc.
			fprintf(logfile , "\n\n***********************Packet*************************\n");
			break;
	}

	print_ethernet_header(Buffer , Size);
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

	return true;
}

void print_tcp_packet(unsigned char* Buffer, int Size, FilterParams* f_params)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
		
	if(!print_ip_header(Buffer, Size, f_params)) return;
	if(f_params->source_port && f_params->source_port!=static_cast<int>(ntohs(tcph->source))) return;
	if(f_params->destination_port && f_params->destination_port!=static_cast<int>(ntohs(tcph->dest))) return;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
						
	fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(unsigned char *Buffer , int Size, FilterParams* f_params)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	if(!print_ip_header(Buffer, Size, f_params)) return;
	if(f_params->source_port && f_params->source_port!=static_cast<int>(ntohs(udph->source))) return;
	if(f_params->destination_port && f_params->destination_port!=static_cast<int>(ntohs(udph->dest))) return;
	
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size, FilterParams* f_params)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	if(!print_ip_header(Buffer, Size, f_params)) return;
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile , "Data Payload\n");	
	
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}

void toLower(std::string &s){
	int l = s.length();
	for(int i=0; i<l; i++) s[i]=tolower(s[i]);
}

int main(int argc, char* argv[])
{
	int proto;
	int sock_raw;
	int source_addr_size , data_size;
	struct sockaddr_in source_addr, dest_addr;
	
	unsigned char *buffer = (unsigned char *) malloc(65536);

	signal(SIGINT, SignalHandler);

	logfile = fopen("analysis.txt","w");
	if(logfile==NULL){
		perror("Unable to create analysis.txt file");
		exit(EXIT_FAILURE);
	}
	printf("Sniffing...\n");
	
	FilterParams* f_params = new FilterParams();
	if(argc>1)
	{
		int i=1;
		while(i<argc){
			if(strcmp(argv[i],"-i")==0){
				i++;
				if(i<argc && argv[i][0]!='-'){
					f_params->protocol.first = argv[i++];
					toLower(f_params->protocol.first);
				}
				if(i<argc && argv[i][0]!='-'){
					f_params->protocol.second = argv[i++];
					toLower(f_params->protocol.second);
				}
			}
			else if(strcmp(argv[i],"-s")==0){
				i++;
				if(i<argc && argv[i][0]!='-'){
					f_params->source_ip = argv[i++];
					toLower(f_params->source_ip);
				}
				if(i<argc && argv[i][0]!='-'){
					f_params->source_port = std::stoi(argv[i++]);
				}
			}
			else if(strcmp(argv[i],"-d")==0){
				i++;
				if(i<argc && argv[i][0]!='-'){
					f_params->destination_ip = argv[i++];
					toLower(f_params->destination_ip);
				}
				if(i<argc && argv[i][0]!='-'){
					f_params->destination_port = std::stoi(argv[i++]);
				}
			}
			else{
				std::cout<<"Cannot identify the arguement type. Dropping the argument. . ."<<std::endl;
				i++;
			}
		}
	}

	if(f_params->protocol.first=="all"){
		proto = ETH_P_ALL;
	}
	if(f_params->protocol.first=="ipv4"){
		proto = ETH_P_IP;
	}
	if(f_params->protocol.first=="ipv6"){
		proto = ETH_P_IPV6;
	}
	if(f_params->protocol.first=="arp"){
		proto = ETH_P_ARP;
	}
	
	if((sock_raw = socket(AF_PACKET , SOCK_RAW , htons(proto))) < 0){
		perror("Socket Error");
		exit(EXIT_FAILURE);
	}

	bzero(&source_addr, sizeof(source_addr));
	bzero(&dest_addr, sizeof(dest_addr));

	while(sniffPackets){
		source_addr_size = sizeof(source_addr);
		
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , (struct sockaddr*)&source_addr , (socklen_t*)&source_addr_size);

		if(data_size < 0){
			perror("Failed to receive packets\n");
			exit(EXIT_FAILURE);
		}
		
		ProcessPacket(buffer , data_size, f_params);
	}
    close(sock_raw);
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
	printf("B-Bye!!\n");
	return 0;
}
