// Ethernet headers are always exactly 14 bytes 
#define SIZE_ETHERNET 14

//Pointers to structs
const struct sniff_Ethernet *Ethernet; // The Ethernet header 
const struct sniff_ip *ip; // The IP header 
const struct sniff_tcp *tcp; // The TCP header 
const char *payload; // Packet payload 

u_int size_ip;
u_int size_tcp;
