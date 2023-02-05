#ifndef DEVICE_SCANNER
#define DEVICE_SCANNER

#include <pcap.h>

extern pcap_if_t *allDevices;
extern pcap_if_t *currentDevice;

extern void getAllDevices();

#endif //DEVICE_SCANNER
