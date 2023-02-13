
#include "Sniffer.h"

#include <pcap.h>
#include <pthread.h>

#include "InterfaceHandler.h"

pthread_t Sniffer_snifferHandle = NULL;

void *Listener(void *lpParam) {
    InterfaceHandler_CapturePackets();
}

void Sniffer_Start(void) {
    pthread_create(&Sniffer_snifferHandle, NULL, Listener, NULL);
}

void Sniffer_CleanUp(void) {
    InterfaceHandler_StopCapturing();
    if (Sniffer_snifferHandle != NULL) {
        (void) pthread_cancel(Sniffer_snifferHandle);
        Sniffer_snifferHandle = NULL;
    }
}
