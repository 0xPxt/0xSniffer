#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "device_scanner.h"
#include "error_handler.h"
#include "globals.h"

pcap_if_t *allDevices;
pcap_if_t *currentDevice;

void getAllDevices() {
    //Find list of nd non-loopback devices
    if(pcap_findalldevs(&allDevices, pcapErrBuff) == PCAP_ERROR) {
        DisplayPcapErrorAndExit("Error scanning for devices", TRUE);
    }
}
