
#include "Sniffer.h"

#include <winsock.h>
#include <pcap.h>

#include "InterfaceHandler.h"

HANDLE Sniffer_snifferHandle = NULL;

DWORD WINAPI Listener(LPVOID pcapHandle) {
    InterfaceHandler_CapturePackets();
}

void Sniffer_Start(void) {
    Sniffer_snifferHandle = CreateThread(NULL, 0, Listener, NULL, 0, NULL);
}

void Sniffer_CleanUp(void) {
    InterfaceHandler_StopCapturing();
    if (CloseHandle(Sniffer_snifferHandle) == 0) {
        ErrorHandler_DisplayWarning("[Sniffer] Could not close the handle for the Sniffer!);
    }
    
}