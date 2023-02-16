#ifndef SNIFFER
#define SNIFFER

#include <pcap.h>

extern void Sniffer_Start(void);

extern void Sniffer_Stop(void);

extern void Sniffer_CleanUp(void);

extern void Sniffer_ParsePacket(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);

#endif // SNIFFER