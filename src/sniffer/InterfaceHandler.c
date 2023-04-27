#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>

#include "InterfaceHandler.h"
#include "ErrorHandler.h"
#include "Sniffer.h"

pcap_if_t *InterfaceHandler_availableInterfaces;
pcap_if_t *InterfaceHandler_currentInterface;
pcap_t *InterfaceHandler_captureHandler;

void InterfaceHandler_Init() {
    // Find list of interfaces available in the system
    if(pcap_findalldevs(&InterfaceHandler_availableInterfaces, ErrorHandler_GetPcapErrorBuffer()) == PCAP_ERROR) {
        ErrorHandler_DisplayPcapErrorAndExit("[InterfaceHandler] Error scanning for devices", true);
    }
}

InterfaceHandler_status_t InterfaceHandler_SelectInterface(int interfaceNumber) {
    int index;
    pcap_if_t *currentIf;

    if (InterfaceHandler_availableInterfaces == NULL) {
        ErrorHandler_DisplayErrorAndExit("[InterfaceHandler] Interfaces not available!");
    } else {
        for (currentIf = InterfaceHandler_availableInterfaces, index = 0; currentIf != NULL; currentIf = currentIf->next, index++) {
            if (interfaceNumber == index) {
                InterfaceHandler_currentInterface = currentIf;
                return InterfaceHandler_status_OK;
            }
        }
    }

    return InterfaceHandler_status_ERROR;
}

InterfaceHandler_status_t InterfaceHandler_OpenCapture() {
    if (InterfaceHandler_currentInterface == NULL) {
        ErrorHandler_DisplayWarning("[InterfaceHandler] Current interface not available!");
        return InterfaceHandler_status_ERROR;
    } else {
        // Prepare capture
        if ((InterfaceHandler_captureHandler = pcap_open_live(InterfaceHandler_currentInterface->name,    // Name of the device.
                                BUFSIZ,                                                                   // Portion of the packet to capture. 
                                                                                                          // Value 65536 grants that the whole packet is captured on all the MACs.
                                1,                                                                        // Promiscuous mode.
                                1000,                                                                     // Read timeout.
                                ErrorHandler_GetPcapErrorBuffer()                                         // Error buffer.
                                )) == NULL)
        {
            ErrorHandler_DisplayPcapErrorAndExit("[InterfaceHandler] Unable to open the adapter. It is not supported by Npcap", true);
        }

        //Link-layer header type values - https://www.tcpdump.org/linktypes.html
        if (pcap_datalink(InterfaceHandler_captureHandler) != DLT_EN10MB) {
            ErrorHandler_DisplayPcapErrorAndExit("[InterfaceHandler] Device does not support Ethernet headers!", false);
        }

        return InterfaceHandler_status_OK;
    }
}

void InterfaceHandler_CapturePackets() {
    if (InterfaceHandler_captureHandler != NULL) {
        pcap_loop(InterfaceHandler_captureHandler, 0, Sniffer_ParsePacket, NULL);
    } else {
        ErrorHandler_DisplayWarning("[InterfaceHandler] There is no capture handle open!");
    }
}

void InterfaceHandler_StopCapturing() {
    if (InterfaceHandler_captureHandler != NULL) {
        pcap_breakloop(InterfaceHandler_captureHandler);
    } else {
        ErrorHandler_DisplayWarning("[InterfaceHandler] Current interface not available!");
    }
}

void InterfaceHandler_PrintInterfaces() {
    int interfaceNumber;
    pcap_if_t *currentIf;

    printf("[INTERFACE LIST]\n\n");

    for (currentIf = InterfaceHandler_availableInterfaces, interfaceNumber = 0; currentIf != NULL; currentIf = currentIf->next, interfaceNumber++) {
        printf("-= %d =- [%s] %s\n", interfaceNumber, currentIf->name, currentIf->description);
    }

    printf("\n");
}

InterfaceHandler_status_t InterfaceHandler_PrintSelectedInterfaceInfo() {
    if (InterfaceHandler_currentInterface == NULL) {
        ErrorHandler_DisplayWarning("[InterfaceHandler] Current interface not available!");
        return InterfaceHandler_status_ERROR;
    } else {
        printf("[%s] %s\n\n", InterfaceHandler_currentInterface->name, InterfaceHandler_currentInterface->description);
        return InterfaceHandler_status_OK;
    }
}

void InterfaceHandler_CleanUp() {
    InterfaceHandler_currentInterface = NULL;

    if (InterfaceHandler_availableInterfaces != NULL) {
        pcap_freealldevs(InterfaceHandler_availableInterfaces);
        InterfaceHandler_availableInterfaces = NULL;
    }

    if (InterfaceHandler_captureHandler != NULL) {
        pcap_close(InterfaceHandler_captureHandler);
        InterfaceHandler_captureHandler = NULL;
    }
}
