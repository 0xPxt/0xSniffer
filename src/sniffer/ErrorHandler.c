
#include "ErrorHandler.h"

#include <stdio.h>
#include <stdlib.h>

#include "InterfaceHandler.h"
#include "IOHandler.h"
#include "Sniffer.h"

char ErrorHandler_pcapErrBuff[PCAP_ERRBUF_SIZE];

static void CleanUpAndExit() {
    Sniffer_CleanUp();
    InterfaceHandler_CleanUp();
    IOHandler_CleanUp();
    ExitProcess(1);
}

void ErrorHandler_DisplayPcapErrorAndExit(char *error_message, bool printErrBuff) {
    printf("-=-=-=-=-=-=-= PCAP ERROR! =-=-=-=-=-=-=-\n");
    printf("%s\n", error_message);
    if (printErrBuff == true) {
        printf("[PCAP ERROR] : %s\n", ErrorHandler_pcapErrBuff);
    }
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");

    CleanUpAndExit();
}

void ErrorHandler_DisplayErrorAndExit(char *error_message) {
    printf("-=-=-=-=-=-=-=-= ERROR =-=-=-=-=-=-=-=-\n");
    printf("[ERROR] : %s\n", error_message);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");

    CleanUpAndExit();
}

void ErrorHandler_DisplayWarning(char *warning_message) {
    printf("-=-=-=-=-=-=-=-=- WARNING -=-=-=-=-=-=-=-=-\n");
    printf("[WARNING] : %s\n", warning_message);
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
}

char *ErrorHandler_GetPcapErrorBuffer() {
    return ErrorHandler_pcapErrBuff;
}

void ErrorHandler_CleanExit() {
    CleanUpAndExit();
}
