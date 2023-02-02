#include <stdio.h>
#include <stdlib.h>
#include "error_handler.h"
#include "globals.h"

char errbuf[PCAP_ERRBUF_SIZE];

void pcap_error(char *error_message) {
    printf("-=-=-=-=-=-=-= PCAP ERROR! =-=-=-=-=-=-=-\n");
    printf("%s\n", error_message);
    printf("[PCAP ERROR] : %s\n", errbuf);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    exit(1);
}

void display_error(char *error_message) {
    printf("-=-=-=-=-=-=-=-=- ERROR -=-=-=-=-=-=-=-=-\n");
    printf("[WARNING] : %s\n", error_message);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=--==-=-=-=-=-=-\n");
}
