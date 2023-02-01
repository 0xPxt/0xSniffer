#include <stdio.h>
#include <stdlib.h>
#include "../device_scanner/device_scanner.h"
#include "../error_handler/error_handler.h"
#include "../globals/globals.h"

int main (int argc, char** argv) {
    char *devices_list[DEVICE_LIST_MAX_SIZE];
    int num_of_devices = 0;
    int errNum = 0;

    #if _WIN32
    // Initialize library to use local encoding
    errNum = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (errNum == PCAP_ERROR) {
        display_error("Could not initialize pcap library!");
    }
    #endif

    num_of_devices = scan_all_available_devices(devices_list);

    for(int i = 0; i < num_of_devices; i++) {
        printf("%s\n", devices_list[i]);
    }
}
