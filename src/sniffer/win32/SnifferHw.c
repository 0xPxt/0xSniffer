
#include "Sniffer.h"

#include <winsock.h>
#include <pcap.h>

#include "InterfaceHandler.h"
#include "ErrorHandler.h"

HANDLE Sniffer_snifferHandle = NULL;

DWORD WINAPI Listener(LPVOID pcapHandle) {
    InterfaceHandler_CapturePackets();
}

void Sniffer_Start() {
    Sniffer_snifferHandle = CreateThread(NULL, 0, Listener, NULL, 0, NULL);
    if (Sniffer_snifferHandle == NULL) {
        ErrorHandler_DisplayErrorAndExit("[Sniffer] Could not start the Sniffer's thread.");
    }
}

void Sniffer_CleanUp() {
    InterfaceHandler_StopCapturing();
    if (CloseHandle(Sniffer_snifferHandle) == 0) {
        ErrorHandler_DisplayWarning("[Sniffer] Could not close the handle for the Sniffer.");
    }
}