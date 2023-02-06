#include <stdio.h>
#include <stdlib.h>
#include "error_handler.h"
#include "globals.h"
#include "device_scanner.h"

char pcapErrBuff[PCAP_ERRBUF_SIZE];

void DisplayPcapErrorAndExit(char *error_message, boolean printErrBuff) {
    printf("-=-=-=-=-=-=-= PCAP ERROR! =-=-=-=-=-=-=-\n");
    printf("%s\n", error_message);
    if (printErrBuff == TRUE) {
        printf("[PCAP ERROR] : %s\n", pcapErrBuff);
    }
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    pcap_freealldevs(allDevices);
    exit(1);
}

void DisplayErrorAndExit(char *error_message) {
    printf("-=-=-=-=-=-=-=-= ERROR =-=-=-=-=-=-=-=-\n");
    printf("[ERROR] : %s\n", error_message);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    pcap_freealldevs(allDevices);
    exit(1);
}

void DisplayWarning(char *warning_message) {
    printf("-=-=-=-=-=-=-=-=- WARNING -=-=-=-=-=-=-=-=-\n");
    printf("[WARNING] : %s\n", warning_message);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
}
