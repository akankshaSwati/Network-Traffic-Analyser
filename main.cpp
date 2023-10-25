#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include<signal.h>

using namespace std;
bool shouldRun = true;  // Initialize a flag

void SignalHandler(int signum) {
    if (signum == SIGINT) {
        shouldRun = false;
        printf("Sniffer Executed Successful!!!\r\n");
        return;
    }
}

int main() {
    // Compile the external_program.cpp
    const char* compileCommand = "g++ sniffer.cpp -o sniffer";

    // Execute the compilation command
    int compileResult = system(compileCommand);

    if (compileResult == 0) {
        std::cout << "Compilation successful." << std::endl;

        // Run the compiled external_program
        const char* runCommand = "./sniffer";
        int runResult = system(runCommand);
        if (runResult == 0) {
			// const char* terminateCommand = "pkill -INT sniffer"; // Replace with the actual program name
        	// int terminateResult = system(terminateCommand);

        	// if (terminateResult == 0) {
            // 	std::cout << "Sniffer terminated successfully." << std::endl;
        	// } else {
            // 	std::cerr << "Sniffer termination failed." << std::endl;
        	// }
            // std::cout << "Log.txt generated." << std::endl;
        } else {
			SignalHandler(SIGINT);
			if(shouldRun==0) return 0;
            std::cerr << "Execution failed." << std::endl;
        }
    } else {
        std::cerr << "Compilation failed." << std::endl;
    }

    return 0;
}