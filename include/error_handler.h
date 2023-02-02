#ifndef ERROR_HANDLER
#define ERROR_HANDLER
#include <pcap.h>

extern char errbuf[PCAP_ERRBUF_SIZE];

void pcap_error(char *error_message);
void display_error(char *error_message);

#endif //ERROR_HANDLER
