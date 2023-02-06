#ifndef ERROR_HANDLER
#define ERROR_HANDLER
#include <pcap.h>
#include <stdbool.h>

extern char pcapErrBuff[PCAP_ERRBUF_SIZE];

extern void DisplayPcapErrorAndExit(char *error_message, bool printErrBuff);
extern void DisplayErrorAndExit(char *error_message);
extern void DisplayWarning(char *warning_message);

#endif //ERROR_HANDLER
