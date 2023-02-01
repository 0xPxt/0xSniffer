#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "device_scanner.h"
#include "../error_handler/error_handler.h"
#include "../globals/globals.h"

char errbuf[PCAP_ERRBUF_SIZE];

int scan_all_available_devices(char **devices_names) {
    pcap_if_t *all_devices;
    pcap_if_t *currentDevice;
    int num_of_devices = 0;

    //Find list of nd non-loopback devices
    if(pcap_findalldevs(&all_devices, errbuf) == PCAP_ERROR) {
        display_error("Error scanning for devices");
    }

    //Assign list to argument buffer
    currentDevice = all_devices;
    while((currentDevice != NULL) && (num_of_devices < DEVICE_LIST_MAX_SIZE)) {
        devices_names[num_of_devices++] = currentDevice->name;
        currentDevice = currentDevice->next;
    }

    return num_of_devices;
}
