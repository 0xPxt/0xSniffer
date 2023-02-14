
#include "Sniffer.h"

#include <pcap.h>
#include <pthread.h>

#include "InterfaceHandler.h"
#include "ErrorHandler.h"

pthread_t Sniffer_snifferHandle = NULL;

void *Listener(void *lpParam) {
    InterfaceHandler_CapturePackets();
}

void Sniffer_Start(void) {
    
    if (pthread_create(&Sniffer_snifferHandle, NULL, Listener, NULL) != 0) {
        ErrorHandler_DisplayErrorAndExit("[Sniffer] Could not create a thread for the Sniffer!");
    }
}

void Sniffer_CleanUp(void) {
    InterfaceHandler_StopCapturing();
    if (Sniffer_snifferHandle != NULL) {
        if (pthread_cancel(Sniffer_snifferHandle) != 0) {
            ErrorHandler_DisplayWarning("[Sniffer] Could not close the handle!");
        }
        Sniffer_snifferHandle = NULL;
    }
}
