#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <cstring>

using namespace std;
bool shouldRun = true;  // Initialize a flag

void SignalHandler(int signum) {
    if (signum == SIGINT) {
        shouldRun = false;
        printf("Sniffer Executeion Successful!!!\r\n");
        return;
    }
}

int main(int argc, char* argv[]) {
    while(1)
    {
        char way;
        std::cout<< "Enter s if you want to capture the packets and analyze.\nEnter f if you want to analyze a file.\nEnter q to quit.\n" <<std::endl;
        std::cin>>way;
        if(way=='s' || way =='S')
        {
            // Compile the external_program.cpp
            const char* compileSniffer = "g++ sniffer.cpp -o sniffer";

            // Execute the compilation command
            int compileSnifferResult = system(compileSniffer);
            if (compileSnifferResult == 0) 
            {
                std::cout << "Sniffer compilation successful." << std::endl;               
                string filters ="./sniffer";
                if(argc<2)
                {
                    std::cout << "No filter criteria found. All the packets in the pcap file will be displayed." << std::endl;
                }
                else
                {
                    for (int i = 1; i < argc; i++) 
                    {
                        filters+=" ";
                        filters= filters+ argv[i];
                    }            
                }
                const char* runSniffer = filters.c_str();
                // Run the compiled external_program
                int runSnifferResult = system(runSniffer);
                if (runSnifferResult == 0 || shouldRun==0) 
                {
                    SignalHandler(SIGINT);                    
                } 
                else if(!shouldRun)
                {
                    std::cerr << "Execution failed." << std::endl;
                }
            } 
            else 
            {
                std::cerr << "Sniffer compilation failed." << std::endl;
            }
            break;
        }
        else if(way=='f' || way=='F')
        {
            //Compiling Filter.cpp
            const char* compileFilter = "g++ filter.cpp -o filter -lpcap";
            int compileFilterResult = system(compileFilter);
            if (compileFilterResult == 0) 
            {
                std::cout << "Filter compilation successful." << std::endl;
                string filters ="./filter";
                if(argc<2)
                {
                    std::cout << "No filter criteria found. All the packets in the pcap file will be displayed." << std::endl;
                }
                else
                {
                    for (int i = 1; i < argc; i++) 
                    {
                        filters+=" ";
                        filters= filters+ argv[i];
                    }            
                }
                const char* runFilter = filters.c_str();
                int runFilterResult = system(runFilter);
                if (runFilterResult == 0) 
                {
                    std::cout << "Filter execution successful." << std::endl;
                } 
                else 
                {
                    std::cerr << "Filter execution failed." << std::endl;
                }
            } 
            else 
            {
                std::cerr << "Filter compilation failed." << std::endl;
            }
            break;
        }
        else if(way=='q' || way=='Q')
        {
            std::cout<<"Terminating the program...."<<std::endl;
            return 0;
        }
        else
        {
            std::cout<<"Invalid input. Try again!!!"<<std::endl;
        }
    }    
    return 0;
}