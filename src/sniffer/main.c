#include <stdio.h>
#include <stdlib.h>

#include "InterfaceHandler.h"
#include "ErrorHandler.h"
#include "IOHandlerMain.h"
#include "Sniffer.h"

#define HAVE_REMOTE

int main (int argc, char** argv) {
    pcap_t *adHandle = NULL;
    int number = 1;

    #ifdef _WIN32
    // Initialize library to use local encoding
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, ErrorHandler_GetPcapErrorBuffer()) == PCAP_ERROR) {
        ErrorHandler_DisplayPcapErrorAndExit("[Main] Could not initialize pcap library!", true);
    }
    #endif // _WIN32

    InterfaceHandler_Init();

    IOHandlerMain_CreateAndStartLogger();

    IOHandlerMain_RequestInterfaceSelection();

    InterfaceHandler_OpenCapture();

    Sniffer_Start();

    for (;;) {
        IOHandlerMain_RequestNewCommand();
    }

    ErrorHandler_CleanExit();
}