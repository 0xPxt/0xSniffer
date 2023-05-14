#include "Packet.h"

#include <pcap.h>

packet_t Packet_listOfPackets[ PACKET_LIST_SIZE ] = { 0 };

uint32_t Packet_numOfPackets = 0;

void Packet_initPacket(packet_t *packet, struct pcap_pkthdr *header, unsigned char *pkt_data) {
    // TODO::@memoryleak police
    packet->id = Packet_numOfPackets;

    packet->header = malloc(sizeof(struct pcap_pkthdr));
    memcpy(packet->header, header, sizeof(struct pcap_pkthdr));

    packet->data = malloc(packet->header->len);
    memcpy(packet->data, pkt_data, packet->header->len);
}

void Packet_addPacketToPacketList(packet_t *packet) {
    Packet_listOfPackets[Packet_numOfPackets++] = *packet;
}

void Packet_packetHexDump(packet_t *packet) {
    //TODO :: Where do we dump this? 
    //          - External file
    //          - New terminal
    //          - Window pop up
    for (int i = 0; i < packet->header->len; i++) {
        printf("%02X ", packet->data[i]);
    }
}