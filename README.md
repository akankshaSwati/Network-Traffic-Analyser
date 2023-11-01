# Network Traffic Analyser
Traffic analysis is the process of monitoring and inspecting network traffic to gain insights, identify issues, and maintain the security and efficiency of a network.

Network Traffic Analyser is a command line tool serving majorly 2 functionalities:

1.  Sniffer-Filter-Analyser →
    Sniffs and filters network frames based over CLI arguments. Further, de-encapsulation and analysis is carried out header by header. Final analysis is provided in "analysis.txt".

2.  Pcap-Filter →
    Takes .pcap file as input, decodes, and filters based on either protocol or source/destination IP address (CLI). Analysis provided via terminal.

## Setup
You can clone the repository using,
```
$~ git clone https://github.com/akankshaSwati/Network-Traffic-Analyser.git
```
Or,
Can simply download the .zip file through the `Code` button above.

## Execution
1. Generate the `main` executable
	```
	$~ g++ 'path-to-main.cpp' -o main
	```
2. Run `main` 
	```
	$~ sudo ./main [OPTIONS]
	```
	PS: You need to run the program as root user, as the code includes creation of raw sockets.
	
### Filtration 
For filtration of network packets, params can be provided through arguments while executing `main`
```
$~ sudo ./main [OPTIONS]
```
[OPTIONS] :
-i `network protocol` `transport protocol` (both arguments being optional)
-s `source ip address` `source port` (source ip address is required* to filter by source port)
-d `destination ip address` `destination port` (destination ip address is required* to filter by destination port)

PS: Any number of filters can be provided in the `OPTIONS` field

### Analysis
Analysis for Sniffer-Filter-Analyser is provided in "analysis.txt"
Analysis for Pcap-Filter is provided via terminal
