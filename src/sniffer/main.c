#include <stdio.h>
#include <stdlib.h>

#include "InterfaceHandler.h"
#include "ErrorHandler.h"
#include "IOHandler.h"
#include "Sniffer.h"

#ifdef __linux__
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#endif

#define HAVE_REMOTE

#ifdef __linux__
int fileDescriptorWrite;
pid_t processPid = 0;
#endif

int main (int argc, char** argv) {
    pcap_t *adHandle = NULL;
    int number = 1;

    #ifdef _WIN32
    // Initialize library to use local encoding
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, ErrorHandler_GetPcapErrorBuffer()) == PCAP_ERROR) {
        ErrorHandler_DisplayPcapErrorAndExit("Could not initialize pcap library!", true);
    }
    #endif // _WIN32

    InterfaceHandler_Init();

    IOHandler_CreateAndStartLogger();

    IOHandler_RequestInterfaceSelection();

    InterfaceHandler_OpenCapture();

    Sniffer_Start();

    for (;;) {
        IOHandler_RequestNewCommand();
    }

    ErrorHandler_CleanExit();

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
#else
void itoa(int n, char s[]);
void reverse(char s[]);

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