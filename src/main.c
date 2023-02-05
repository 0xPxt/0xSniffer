#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "device_scanner.h"
#include "error_handler.h"
#include "globals.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock.h>
#endif

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

static void DeviceSelectionMenu();
static inline void ClearScreen();
static void DisplayBanner();

void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void StartDeviceSniffer();

int main (int argc, char** argv) {
    int errNum = 0;
    int selected_device_index;
    #ifdef _WIN32

    // Initialize library to use local encoding
    errNum = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (errNum == PCAP_ERROR) {
        pcap_error("Could not initialize pcap library!");
    }
    #endif

    getAllDevices();

    DeviceSelectionMenu();

    StartDeviceSniffer();

    pcap_freealldevs(allDevices);
}

void StartDeviceSniffer() {
    pcap_t *adhandle;
    int i;

	if ((adhandle = pcap_open_live(currentDevice->name,	// name of the device
							BUFSIZ,			            // portion of the packet to capture. 
											            // 65536 grants that the whole packet will be captured on all the MACs.
							1,				            // promiscuous mode (nonzero means promiscuous)
							1000,			            // read timeout
							errbuf			            // error buffer
							)) == NULL)
	{
		pcap_error("Unable to open the adapter. It is not supported by Npcap");
	}
	
	printf("\nListening on [%s] %s...\n", currentDevice->name, currentDevice->description);

    //Link-layer header type values - https://www.tcpdump.org/linktypes.html
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        pcap_error("Device does not support Ethernet headers!");
    }

    pcap_loop(adhandle, 0, PacketHandler, NULL);

    pcap_close(adhandle);
}

static int RequestDeviceSelection(int *selection) {
    int numberOfDevices;
    pcap_if_t *device;

    printf("\n");
    printf("Select one of your devices to sniff the network :\n");
    printf("\n");
    
    for(device = allDevices, numberOfDevices = 0; device != NULL; device = device->next, numberOfDevices++) {
        printf("-= %d =- [%s] %s\n", numberOfDevices, device->name, device->description);
    }

    printf("\n");
    printf("Enter the number and press ENTER: ");

    scanf("%d", selection);

    return numberOfDevices;
}

static void DeviceSelectionMenu() {
    int selection, numberOfDevices = -1;
    int i;

    DisplayBanner();

    numberOfDevices = RequestDeviceSelection(&selection);

    while ((selection < 0) || (selection >= numberOfDevices)) {

        DisplayBanner();

        display_error("Please choose a valid number");

        numberOfDevices = RequestDeviceSelection(&selection);
    }

    DisplayBanner();

    // Option chosen correctly, commit device selection
    for(currentDevice = allDevices, i = 0; i < selection; currentDevice = currentDevice->next, i++);

    printf("\nYou have selected : [%s] %s\n", currentDevice->name, currentDevice->description);
}

static inline void ClearScreen() {
    printf("\033[2J\033[1;1H");
}

static void DisplayBanner() {
    ClearScreen();

    printf("\n");
    printf("\n");
    printf("╔═══╗    ╔═══╗       ╔═╗ ╔═╗\n");
    printf("║╔═╗║    ║╔═╗║       ║╔╝ ║╔╝\n");
    printf("║║ ║║╔╗╔╗║╚══╗╔═╗ ╔╗╔╝╚╗╔╝╚╗╔══╗╔═╗\n");
    printf("║║ ║║╚╬╬╝╚══╗║║╔╗╗╠╣╚╗╔╝╚╗╔╝║╔╗║║╔╝\n");
    printf("║╚═╝║╔╬╬╗║╚═╝║║║║║║║ ║║  ║║ ║║═╣║║\n");
    printf("╚═══╝╚╝╚╝╚═══╝╚╝╚╝╚╝ ╚╝  ╚╝ ╚══╝╚╝\n");
    printf("\n");
    printf("\n");
}

void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}
