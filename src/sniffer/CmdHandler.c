
#include "CmdHandler.h"

#include <stdio.h>

#include "ErrorHandler.h"
#include "LogUtils.h"

int CmdHandler_SaveLogAsTxt();

CmdHandler_status_t CmdHandler_ProcessCommand(CmdHandler_cmdCode_t command) {
    char fileName[32] = {' '};

    switch(command) {
        case CmdHandler_cmdCode_EXIT: {
            ErrorHandler_CleanExit();
            break;
        }

        case CmdHandler_cmdCode_SAVE: {
            LogUtils_RequestFileName(fileName);
            if(CmdHandler_SaveLogAsTxt(fileName) != 0) {
                ErrorHandler_DisplayWarning("Couldn't save file!");
            }
            break;
        }

        case CmdHandler_cmdCode_LIST: {

            break;
        }

        case CmdHandler_cmdCode_IDLE: {
            printf("IDLE!\n");
            break;
        }

        default: {
            return CmdHandler_status_UNKNOWN_COMMAND;
        }
    }

    return CmdHandler_status_OK;
}

void CmdHandler_PrintCommandList() {
    printf("[COMMAND LIST]\n\n");

    printf("-= %d =- [IDLE] Do nothing...\n", (int) CmdHandler_cmdCode_IDLE);
    printf("-= %d =- [EXIT] Safely exits the program.\n", (int) CmdHandler_cmdCode_EXIT);
    printf("-= %d =- [SAVE] Save the log to a .txt file.\n", (int) CmdHandler_cmdCode_SAVE);
    printf("-= %d =- [LIST] List the last 10 captured Packets' IDs.\n", (int) CmdHandler_cmdCode_LIST);

    printf("\n");
}

int CmdHandler_SaveLogAsTxt(char* fileDest) {
    int   c;
    FILE *stream_R;
    FILE *stream_W; 

    stream_R = fopen ("log_tmp.txt", "r");
    if (stream_R == NULL)
        return -1;
    stream_W = fopen (fileDest, "w");   //create and write to file
    if (stream_W == NULL)
     {
        fclose (stream_R);
        return -2;
     }    
    while ((c = fgetc(stream_R)) != EOF)
        fputc (c, stream_W);
    fclose (stream_R);
    fclose (stream_W);

    return 0;
}
