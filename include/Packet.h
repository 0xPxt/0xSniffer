#include <pcap.h>

#define PACKET_LIST_SIZE 0xFFFFFF // 16,777,215

typedef struct {
    uint32_t id;            // Max value : 4,294,967,295
    struct pcap_pkthdr *header;
    unsigned char *data;
} packet_t;