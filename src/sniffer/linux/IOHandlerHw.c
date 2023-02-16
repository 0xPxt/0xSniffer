
#include "IOHandler.h"

#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "ErrorHandler.h"

#define PIPE_READ_END 0
#define PIPE_WRITE_END 1

#define ERROR_MESSAGE_BUFFER_SIZE 128

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

void IOHandler_CreateAndStartLogger() {
    int pipeFileDescriptor[2];   
    char buffer[16];

    // Open pipe
    if (pipe(pipeFileDescriptor) == -1) {
        ErrorHandler_DisplayErrorAndExit("[IOHandler] Could not open a pipe for the Logger.");
    }

    // Create child process
    if ((IOHandler_loggerProcessId = fork()) < 0) {
        ErrorHandler_DisplayErrorAndExit("[IOHandler] Coluld not fork into a process for the Logger.");
    }

    // Discern between process
    if (IOHandler_loggerProcessId == 0) {
        // Child process
        // Close write end of the pipe (Logger will not be writing into the pipe)
        if (close(pipeFileDescriptor[PIPE_WRITE_END]) == -1) {
            ErrorHandler_DisplayWarning("[IOHandler] Could not close the write end of the Loggers pipe.");
        }

        // Execute logger.c
        itoa(pipeFileDescriptor[0], buffer);
        if (execl("./Logger", buffer, NULL) < 0) {
            ErrorHandler_DisplayErrorAndExit("[IOHandler] Coluld not execute the logger.");
        }
    } else {
        // Parent process
        // Close write end of the pipe (Sniffer will not be reading from the pipe)
        if (close(pipeFileDescriptor[PIPE_READ_END]) == -1) {
            ErrorHandler_DisplayWarning("[IOHandler] Could not close the read end of the Loggers pipe.");
        }

        IOHandler_loggerStdInWr = pipeFileDescriptor[PIPE_WRITE_END];
    }
}

void IOHandler_WriteToLogger(void *packet, unsigned long packetLength) {
    ssize_t bytesWritten = write(IOHandler_loggerStdInWr, packet, (size_t) packetLength);
    if (bytesWritten != (ssize_t) packetLength) {
        if (bytesWritten < 0) {
            char buffer[ERROR_MESSAGE_BUFFER_SIZE];
            if (sprintf(buffer, "[IOHandler] Only %d/%d bytes where sent to the Logger.", bytesWritten, packetLength) < 0) {
                ErrorHandler_DisplayWarning("[IOHandler] Only a part of the packet has been sent to the Logger.");
            } else {
                ErrorHandler_DisplayWarning(buffer);
            }
        } else {
            ErrorHandler_DisplayWarning("[IOHandler] Error sending a packet to the Logger.");
        }
    }
}

void IOHandler_CleanUp() {
    if (close(IOHandler_loggerStdInWr) != 0) {
        ErrorHandler_DisplayWarning("[IOHandler] Could not close the logger's write handle.");
    }
}