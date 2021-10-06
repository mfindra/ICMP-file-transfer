#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

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

int main(int argc, char** argv) {
    int DEBUG = 1;

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
                return 1;
        }
    }

    // check if application runs in listen (-l) mode
    if (L_opt) {
        cout << "Listen mode";
        return 0;
    } else {
        // check arguments in sender mode
        if (R_opt.empty()) {
            fprintf(stderr, "ERROR - Missing file name!\n");
            return 1;
        } else if (S_opt.empty()) {
            fprintf(stderr, "ERROR - Missing IP address or hostname!\n");
            return 1;
        }

        //
        ifstream f(R_opt.c_str());
        if (f.good()) {
            cout << "File extists" << endl;
        } else {
            fprintf(stderr, "ERROR - File not found\n");
            return 1;
        }

        f.close();
    }

    if (DEBUG) {
        cout << "R_opt = " << R_opt << endl;
        cout << "S_opt = " << S_opt << endl;
        cout << "L_opt = " << L_opt << endl;
    }

    return 0;
}