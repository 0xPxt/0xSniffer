
#include "IOHandler.h"

#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "ErrorHandler.h"

#define PIPE_READ_END 0
#define PIPE_WRITE_END 1

int IOHandler_loggerStdInWr;
pid_t IOHandler_loggerProcessId;

/* reverse:  reverse string s in place */
static void reverse(char s[])
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
static void itoa(int n, char s[])
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

void IOHandler_CreateAndStartLogger(void) {
    int pipeFileDescriptor[2];   
    char buffer[16];

    // Open pipe
    if (pipe(pipeFileDescriptor) == -1) {
        ErrorHandler_DisplayErrorAndExit("Could not open a pipe for the Logger!");
    }

    // Create child process
    if ((IOHandler_loggerProcessId = fork()) < 0) {
        ErrorHandler_DisplayErrorAndExit("Coluld not fork into a process for the Logger!");
    }

    // Discern between process
    if (IOHandler_loggerProcessId == 0) {
        // Child process
        // Close write end of the pipe (Logger will not be writing into the pipe)
        close(pipeFileDescriptor[PIPE_WRITE_END]);

        // Execute logger.c
        itoa(pipeFileDescriptor[0], buffer);
        if (execl("./Logger", buffer, NULL) < 0) {
            ErrorHandler_DisplayErrorAndExit("Coluld not execute the logger!");
        }
    } else {
        // Parent process
        // Close write end of the pipe (Sniffer will not be reading from the pipe)
        close(pipeFileDescriptor[PIPE_READ_END]);

        IOHandler_loggerStdInWr = pipeFileDescriptor[PIPE_WRITE_END];
    }
}

void IOHandler_WriteToLogger(void *packet, unsigned long packetLength) {
    (void) write(IOHandler_loggerStdInWr, packet, packetLength);
}

void IOHandler_CleanUp() {
    if (close(IOHandler_loggerStdInWr) != 0) {
        ErrorHandler_DisplayWarning("[IOHandler] Could not close the logger's write handle!);
    }
}