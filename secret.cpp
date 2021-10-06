#include <unistd.h>

#include <iostream>
#include <string>

using namespace std;

int main(int argc, char** argv) {
    int DEBUG = 1;

    string R_opt;
    string S_opt;
    bool L_opt = false;

    int opt;
    while ((opt = getopt(argc, argv, "r:s:l")) != -1) {
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
            default:
                fprintf(stderr, "ERROR - Wrong argument!\n");
                return 1;
        }
    }

    if (DEBUG) {
        cout << "R_opt = " << R_opt << endl;
        cout << "S_opt = " << S_opt << endl;
        cout << "L_opt = " << L_opt << endl;
    }

    return 0;
}