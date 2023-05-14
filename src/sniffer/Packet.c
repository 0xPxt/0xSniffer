#include "Packet.h"

#include <pcap.h>

packet_t Packet_listOfPackets[ PACKET_LIST_SIZE ] = { NULL };
uint32_t Packet_numOfPackets = 0;

void Packet_addPacketToPacketList(const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    packet_t packet;
    packet.id = Packet_numOfPackets;
    packet.header = header;
    packet.data = pkt_data;
    Packet_listOfPackets[Packet_numOfPackets++] = packet;
}

void Packet_packetHexDump(packet_t packet) {

}