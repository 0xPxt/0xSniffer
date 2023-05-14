#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define BUFSIZE 4096

int main(void) {
    HANDLE hStdin;
    DWORD dwRead;
    BOOL bSuccess;
    CHAR chBuf[BUFSIZE];
    FILE *log = fopen("log_tmp.txt", "w");

    if (log == NULL)
    {
        printf("Error creating log file!\n");
        ExitProcess(1);
    }

    hStdin = GetStdHandle(STD_INPUT_HANDLE);

    if (hStdin == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    for(;;) {
        // Read from standard input and stop on error or no data.
        bSuccess = ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL);

        if (!bSuccess) {
            break;
        }

        printf("%s\n", chBuf);
        fprintf(log, "%s\n", chBuf);

        //TODO
        /*
        if (exitProgram) {
            fclose(log);
            remove(log_tmp.txt);
        }
        */
    }

    return 0;
}