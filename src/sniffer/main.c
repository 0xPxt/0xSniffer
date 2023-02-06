#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "device_scanner.h"
#include "error_handler.h"
#include "globals.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock.h>
#endif

#ifdef __linux__
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#endif

 void itoa(int n, char s[]);
 void reverse(char s[]);

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

#ifdef _WIN32
HANDLE g_hChildStd_IN_Rd;
HANDLE g_hChildStd_IN_Wr;
#endif

#ifdef __linux__
int fileDescriptorWrite;
pid_t processPid = 0;
#endif

static void DeviceSelectionMenu();
static inline void ClearScreen();
static void DisplayBanner();
static void CreateAndStartLogger();
static void WriteToPipe(void *msg, unsigned long msgLength);

void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
pcap_t *StartDeviceSniffer();

int main (int argc, char** argv) {
    int errNum = 0;
    pcap_t *adHandle = NULL;
    int number = 1;

    #ifdef _WIN32
    // Initialize library to use local encoding
    errNum = pcap_init(PCAP_CHAR_ENC_LOCAL, pcapErrBuff);
    if (errNum == PCAP_ERROR) {
        DisplayPcapErrorAndExit("Could not initialize pcap library!", true);
    }
    #endif

    getAllDevices();

    DeviceSelectionMenu();

    CreateAndStartLogger();

    adHandle = StartDeviceSniffer();

    do {
        DisplayBanner();
        printf("Currently listening on [%s] %s\n\n", currentDevice->name, currentDevice->description);
        printf("Enter 0 to exit application: ");

        scanf("%d", &number);
    } while (number != 0);

    pcap_breakloop(adHandle);

    pcap_freealldevs(allDevices);

    #ifdef __linux__
    if (fileDescriptorWrite != 0) {
        // Close pipe
        close(fileDescriptorWrite);
    }

    if (processPid > 1) {
        // Terminate logger
        kill(processPid, SIGTERM);
    }
    #endif
}

#ifdef _WIN32
DWORD WINAPI Sniffer(LPVOID lpParam) {
    pcap_t *handle = (pcap_t *)lpParam;
    pcap_loop(handle, 0, PacketHandler, NULL);
}

pcap_t *StartDeviceSniffer() {
    HANDLE thread;
    pcap_t *adhandle;

    // Prepare capture
    if ((adhandle = pcap_open_live(currentDevice->name,	// name of the device
							BUFSIZ,			            // portion of the packet to capture. 
											            // 65536 grants that the whole packet will be captured on all the MACs.
							1,				            // promiscuous mode (nonzero means promiscuous)
							1000,			            // read timeout
							pcapErrBuff			            // error buffer
							)) == NULL)
	{
		DisplayPcapErrorAndExit("Unable to open the adapter. It is not supported by Npcap", true);
	}

    //Link-layer header type values - https://www.tcpdump.org/linktypes.html
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        DisplayPcapErrorAndExit("Device does not support Ethernet headers!", false);
    }

    thread = CreateThread(NULL, 0, Sniffer, (LPVOID)adhandle, 0, NULL);

    return adhandle;
}

void CreateChildProcess() {
    TCHAR szCmdline[] = TEXT("Logger");
    PROCESS_INFORMATION piProcInfo; 
    STARTUPINFO siStartInfo;
    BOOL bSuccess = false; 

    // Set up members of the PROCESS_INFORMATION structure.

    ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );

    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.

    ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
    siStartInfo.cb = sizeof(STARTUPINFO); 
    siStartInfo.hStdError = NULL;
    siStartInfo.hStdOutput = NULL;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 

    bSuccess = CreateProcess(NULL, 
        szCmdline,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        true,          // handles are inherited 
        CREATE_NEW_CONSOLE,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION 

    // If an error occurs, exit the application. 
    if (!bSuccess) {
        DisplayErrorAndExit("CreateProcess");
    } else {
        // Close handles to the child process and its primary thread.
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        // Close handles to the stdin and stdout pipes no longer needed by the child process.
        // If they are not explicitly closed, there is no way to recognize that the child process has ended.

        CloseHandle(g_hChildStd_IN_Rd);
    }
}

static void WriteToPipe(void *msg, unsigned long msgLength) {
    (void) WriteFile(g_hChildStd_IN_Wr, msg, msgLength, NULL, NULL);
}

static void CreateAndStartLogger() {
    SECURITY_ATTRIBUTES saAttr;

    // Set the bInheritHandle flag so pipe handles are inherited
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = true;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDIN. 
 
    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) 
        DisplayErrorAndExit("Stdin CreatePipe"); 

    // Ensure the write handle to the pipe for STDIN is not inherited. 
 
    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
        DisplayErrorAndExit("Stdin SetHandleInformation"); 

    // Create the child process. 
   
    CreateChildProcess();

    CloseHandle(g_hChildStd_IN_Rd);
}
#else
void *Sniffer(void *lpParam) {
    pcap_t *handle = (pcap_t *)lpParam;
    pcap_loop(handle, 0, PacketHandler, NULL);
}

pcap_t *StartDeviceSniffer() {
    pthread_t thread_id;
    pcap_t *adhandle;

    // Prepare capture
    if ((adhandle = pcap_open_live(currentDevice->name,	// name of the device
							BUFSIZ,			            // portion of the packet to capture. 
											            // 65536 grants that the whole packet will be captured on all the MACs.
							1,				            // promiscuous mode (nonzero means promiscuous)
							1000,			            // read timeout
							pcapErrBuff			            // error buffer
							)) == NULL)
	{
		DisplayPcapErrorAndExit("Unable to open the adapter. It is not supported by Npcap", true);
	}

    //Link-layer header type values - https://www.tcpdump.org/linktypes.html
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        DisplayPcapErrorAndExit("Device does not support Ethernet headers!", false);
    }

    pthread_create(&thread_id, NULL, Sniffer, (void *)adhandle);


}

void CreateChildProcess() {
}

static void WriteToPipe(void *msg, unsigned long msgLength) {
    write(fileDescriptorWrite, msg, msgLength);
}

#define PIPE_READ_END 0
#define PIPE_WRITE_END 1

static void CreateAndStartLogger() {
    int pipeFileDescriptor[2];   
    char buffer[16];

    // Open pipe
    if (pipe(pipeFileDescriptor) == -1) {
        DisplayErrorAndExit("Could not open a pipe for the Logger!");
    }

    // Create child process
    if ((processPid = fork()) < 0) {
        DisplayErrorAndExit("Coluld not fork into a process for the Logger!");
    }

    // Discern between process
    if (processPid == 0) {
        // Child process
        // Close write end of the pipe (Logger will not be writing into the pipe)
        close(pipeFileDescriptor[PIPE_WRITE_END]);

        // Execute logger.c
        itoa(pipeFileDescriptor[0], buffer);
        if (execl("./Logger", buffer, (char*) NULL) < 0) {
            DisplayErrorAndExit("Coluld not execute the logger!");
        }
    } else {
        // Parent process
        // Close write end of the pipe (Sniffer will not be reading from the pipe)
        close(pipeFileDescriptor[PIPE_READ_END]);

        fileDescriptorWrite = pipeFileDescriptor[PIPE_WRITE_END];
    }
}
#endif

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

        DisplayWarning("Please choose a valid number");

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

#define WRITE_BUFFER_SIZE 1024

void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    char writeBuffer[WRITE_BUFFER_SIZE] = {' '};
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
	(void)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	sprintf(writeBuffer, "%s.%.6ld len:%d ", timestr, header->ts.tv_usec, header->len);

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
	sprintf(writeBuffer, "%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
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

    // Write to the pipe that is the standard input for a child process. 
    // Data is written to the pipe's buffers, so it is not necessary to wait
    // until the child process is running before writing data.

    WriteToPipe(writeBuffer, WRITE_BUFFER_SIZE);
}

 /* reverse:  reverse string s in place */
 void reverse(char s[])
 {
     int i, j;
     char c;

     for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
         c = s[i];
         s[i] = s[j];
         s[j] = c;
     }
 }

 /* itoa:  convert n to characters in s */
 void itoa(int n, char s[])
 {
     int i, sign;

     if ((sign = n) < 0)  /* record sign */
         n = -n;          /* make n positive */
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     if (sign < 0)
         s[i++] = '-';
     s[i] = '\0';
     reverse(s);
 }
