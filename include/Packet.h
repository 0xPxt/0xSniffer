#ifndef PACKETH
#define PACKETH

#include <pcap.h>

#define PACKET_LIST_SIZE 0xFFFF // TODO::review size

typedef struct {
    uint32_t id;            // Max value : 4,294,967,295
    struct pcap_pkthdr *header;
    unsigned char *data;
} packet_t;

extern packet_t Packet_listOfPackets[ PACKET_LIST_SIZE ];

extern uint32_t Packet_numOfPackets;

extern void Packet_addPacketToPacketList(packet_t *packet);

extern void Packet_initPacket(packet_t *packet, struct pcap_pkthdr *header, unsigned char *pkt_data);

extern void Packet_packetHexDump(packet_t *packet);

#endif // PACKETH