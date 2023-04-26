#include "Sniffer.h"

#include <pcap.h>
#include <time.h>
#include <string.h>

#include "IOHandler.h"

#define WRITE_BUFFER_SIZE 1024

char protocols[145][16] = {
    "HOPOPT         ",    //IPv6 Hop-by-Hop Option
    "ICMP           ",    //Internet Control Message
    "IGMP           ",    //Internet Group Management
    "GGP            ",    //Gateway-to-Gateway
    "IPv4           ",    //IPv4 encapsulation
    "ST             ",    //Stream
    "TCP            ",    //Transmission Control
    "CBT            ",    //CBT
    "EGP            ",    //Exterior Gateway Protocol any private interior gateway
    "IGP            ",    //(used by Cisco for their IGRP)
    "BBN-RCC-MON    ",    //BBN RCC Monitoring
    "NVP-II         ",    //Network Voice Protocol
    "PUP            ",    //PUP
    "ARGUS          ",    //ARGUS
    "EMCON          ",    //EMCON
    "XNET           ",    //Cross Net Debugger
    "CHAOS          ",    //Chaos
    "UDP            ",    //User Datagram
    "MUX            ",    //Multiplexing
    "DCN-MEAS       ",    //DCN Measurement Subsystems
    "HMP            ",    //Host Monitoring
    "PRM            ",    //Packet Radio Measurement
    "XNS-IDP        ",    //XEROX NS IDP
    "TRUNK-1        ",    //Trunk-1
    "TRUNK-2        ",    //Trunk-2
    "LEAF-1         ",    //Leaf-1
    "LEAF-2         ",    //Leaf-2
    "RDP            ",    //Reliable Data Protocol
    "IRTP           ",    //Internet Reliable Transaction
    "ISO-TP4        ",    //ISO Transport Protocol Class 4
    "NETBLT         ",    //Bulk Data Transfer Protocol
    "MFE-NSP        ",    //MFE Network Services Protocol
    "MERIT-INP      ",    //MERIT Internodal Protocol
    "DCCP           ",    //Datagram Congestion Control Protocol
    "3PC            ",    //Third Party Connect Protocol
    "IDPR           ",    //Inter-Domain Policy Routing Protocol
    "XTP            ",    //XTP
    "DDP            ",    //Datagram Delivery Protocol
    "IDPR-CMTP      ",    //IDPR Control Message Transport Protocol
    "TP++           ",    //TP++ Transport Protocol
    "IL             ",    //IL Transport Protocol
    "IPv6           ",    //IPv6 encapsulation
    "SDRP           ",    //Source Demand Routing Protocol
    "IPv6-Route     ",    //Routing Header for IPv6
    "IPv6-Frag      ",    //Fragment Header for IPv6
    "IDRP           ",    //Inter-Domain Routing Protocol
    "RSVP           ",    //Reservation Protocol
    "GRE            ",    //Generic Routing Encapsulation
    "DSR            ",    //Dynamic Source Routing Protocol
    "BNA            ",    //BNA
    "ESP            ",    //Encap Security Payload
    "AH             ",    //Authentication Header
    "I-NLSP         ",    //Integrated Net Layer Security TUBA
    "SWIPE          ",    //IP with Encryption
    "NARP           ",    //NBMA Address Resolution Protocol
    "MOBILE         ",    //IP Mobility Transport Layer Security
    "TLSP           ",    //Protocol using Kryptonet key management
    "SKIP           ",    //SKIP
    "IPv6-ICMP      ",    //ICMP for IPv6
    "IPv6-NoNxt     ",    //No Next Header for IPv6
    "IPv6-Opts      ",    //Destination Options for IPv6
    "               ",    //any host internal protocol
    "CFTP           ",    //CFTP
    "               ",    //any local network
    "SAT-EXPAK      ",    //SATNET and Backroom EXPAK
    "KRYPTOLAN      ",    //Kryptolan
    "RVD            ",    //MIT Remote Virtual DiskProtocol
    "IPPC           ",    //Internet Pluribus Packet Core
    "               ",    //any distributed file system
    "SAT-MON        ",    //SATNET Monitoring
    "VISA           ",    //VISA Protocol
    "IPCV           ",    //Internet Packet Core Utility
    "CPNX           ",    //Computer Protocol Network Executive
    "CPHB           ",    //Computer Protocol Heart Beat
    "WSN            ",    //Wang Span Network
    "PVP            ",    //Packet Video Protocol
    "BR-SAT-MON     ",    //Backroom SATNET Monitoring
    "SUN-ND         ",    //SUN ND PROTOCOL-Temporary
    "WB-MON         ",    //WIDEBAND Monitoring
    "WB-EXPAK       ",    //WIDEBAND EXPAK
    "ISO-IP         ",    //ISO Internet Protocol
    "VMTP           ",    //VMTP
    "SECURE-VMTP    ",    //SECURE-VMTP
    "VINES          ",    //VINES
    "IPTM           ",    //Internet Protocol Traffic Manager
    "NSFNET-IGP     ",    //NSFNET-IGP
    "DGP            ",    //Dissimilar Gateway Protocol
    "TCF            ",    //TCF
    "EIGRP          ",    //EIGRP
    "OSPFIGP        ",    //OSPFIGP
    "Sprite-RPC     ",    //Sprite RPC Protocol
    "LARP           ",    //Locus Address Resolution Protocol
    "MTP            ",    //Multicast Transport Protocol
    "AX.25          ",    //AX.25 Frames
    "IPIP           ",    //IP-within-IP Encapsulation Protocol
    "MICP           ",    //Mobile Internetworking Control Pro.
    "SCC-SP         ",    //Semaphore Communications Sec. Pro.
    "ETHERIP        ",    //Ethernet-within-IP Encapsulation
    "ENCAP          ",    //Encapsulation Header
    "               ",    //any private encryption scheme
    "GMTP           ",    //GMTP
    "IFMP           ",    //Ipsilon Flow Management Protocol
    "PNNI           ",    //PNNI over IP
    "PIM            ",    //Protocol Independent Multicast
    "ARIS           ",    //ARIS
    "SCPS           ",    //SCPS
    "QNX            ",    //QNX
    "A/N            ",    //Active Networks
    "IPComp         ",    //IP Payload Compression Protocol
    "SNP            ",    //Sitara Networks Protocol
    "Compaq-Peer    ",    //Compaq Peer Protocol
    "IPX-in-IP      ",    //IPX in IP
    "VRRP           ",    //Virtual Router Redundancy Protocol
    "PGM            ",    //PGM Reliable Transport Protocol
    "               ",    //any 0-hop protocol
    "L2TP           ",    //Layer Two Tunneling Protocol
    "DDX            ",    //D-II Data Exchange (DDX)
    "IATP           ",    //Interactive Agent Transfer Protocol
    "STP            ",    //Schedule Transfer Protocol
    "SRP            ",    //SpectraLink Radio Protocol
    "UTI            ",    //UTI
    "SMP            ",    //Simple Message Protocol
    "SM             ",    //Simple Multicast Protocol
    "PTP            ",    //Performance Transparency Protocol
    "ISIS over IPv4 ",    //
    "FIRE           ",    //
    "CRTP           ",    //Combat Radio Transport Protocol
    "CRUDP          ",    //Combat Radio User Datagram
    "SSCOPMCE       ",    //
    "IPLT           ",    //
    "SPS            ",    //Secure Packet Shield
    "PIPE           ",    //Private IP Encapsulation within IP
    "SCTP           ",    //Stream Control Transmission Protocol
    "FC             ",    //Fibre Channel
    "RSVP-E2E-IGNORE",    //
    "Mobility Header",    //
    "UDPLite        ",    //
    "MPLS-in-IP     ",    //
    "manet          ",    //MANET Protocols
    "HIP            ",    //Host Identity Protocol
    "Shim6          ",    //Shim6 Protocol
    "WESP           ",    //Wrapped Encapsulating Security Payload
    "ROHC           ",    //Robust Header Compression
    "Ethernet       ",    //Ethernet
    "AGGFRAG        ",    //AGGFRAG encapsulation payload for ESP
};

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
    u_char    ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char    tos;            // Type of service
    u_short tlen;            // Total length
    u_short identification; // Identification
    u_short flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
    u_char    ttl;            // Time to live
    u_char    proto;            // Protocol
    u_short crc;            // Header checksum
    ip_address    saddr;        // Source address
    ip_address    daddr;        // Destination address
    u_int    op_pad;            // Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header
{
    u_short sport;            // Source port
    u_short dport;            // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
} udp_header;

void Sniffer_prepareAddressesForPrinting(char* src_ip, char* dest_ip, ip_header* ih, u_short sport, u_short dport);

void Sniffer_Stop() {
    Sniffer_CleanUp();
}

void Sniffer_ParsePacket(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    char writeBuffer[WRITE_BUFFER_SIZE] = {' '};
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;
    char src_ip_string[100] = "";
    char dest_ip_string[100] = "";

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data +
        14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    Sniffer_prepareAddressesForPrinting(src_ip_string, dest_ip_string, ih, sport, dport);

    /* print ip addresses and udp ports */
    sprintf(writeBuffer + strlen(writeBuffer), "\n------------------------------------------------------------\n");
    sprintf(writeBuffer + strlen(writeBuffer), "%*s\t -> \t%*s\n\n",
        20,                // Format so that the string always occupies 20 chars.
        src_ip_string,
        20,                // Format so that the string always occupies 20 chars.
        dest_ip_string);

    // Print Protocol
    sprintf(writeBuffer + strlen(writeBuffer), "  Protocol  : %s\n",
        protocols[ih->proto]);

    // Print TTL
    sprintf(writeBuffer + strlen(writeBuffer), "  TTL       : %d\n", ih->ttl);

    // Print packet length
    sprintf(writeBuffer + strlen(writeBuffer), "  Length    : %d\n", header->len);

    // Print timestamp
    sprintf(writeBuffer + strlen(writeBuffer), "  Time      : %s.%.6ld\n", timestr, header->ts.tv_usec);
    sprintf(writeBuffer + strlen(writeBuffer), "------------------------------------------------------------\n");

    // Write to the pipe that is the standard input for a child process.
    // Data is written to the pipe's buffers, so it is not necessary to wait
    // until the child process is running before writing data.

    IOHandler_WriteToLogger(writeBuffer, WRITE_BUFFER_SIZE);
}

void Sniffer_prepareAddressesForPrinting(char* src_ip, char* dest_ip, ip_header* ih, u_short sport, u_short dport) {
    char ip_addr_formatted[10][5];

    // Convert values to strings
    itoa(ih->saddr.byte1, ip_addr_formatted[0],10);
    itoa(ih->saddr.byte2, ip_addr_formatted[1],10);
    itoa(ih->saddr.byte3, ip_addr_formatted[2],10);
    itoa(ih->saddr.byte4, ip_addr_formatted[3],10);
    itoa(sport,           ip_addr_formatted[4],10);
    itoa(ih->daddr.byte1, ip_addr_formatted[5],10);
    itoa(ih->daddr.byte2, ip_addr_formatted[6],10);
    itoa(ih->daddr.byte3, ip_addr_formatted[7],10);
    itoa(ih->daddr.byte4, ip_addr_formatted[8],10);
    itoa(dport,           ip_addr_formatted[9],10);

    // Put those strings inside the corresponding buffers

    // Source @IP
    strcat(src_ip, ip_addr_formatted[0]);
    strcat(src_ip, ".");
    strcat(src_ip, ip_addr_formatted[1]);
    strcat(src_ip, ".");
    strcat(src_ip, ip_addr_formatted[2]);
    strcat(src_ip, ".");
    strcat(src_ip, ip_addr_formatted[3]);
    strcat(src_ip, ":");
    strcat(src_ip, ip_addr_formatted[4]);

    // Destination @IP
    strcat(dest_ip, ip_addr_formatted[5]);
    strcat(dest_ip, ".");
    strcat(dest_ip, ip_addr_formatted[6]);
    strcat(dest_ip, ".");
    strcat(dest_ip, ip_addr_formatted[7]);
    strcat(dest_ip, ".");
    strcat(dest_ip, ip_addr_formatted[8]);
    strcat(dest_ip, ":");
    strcat(dest_ip, ip_addr_formatted[9]);
}
