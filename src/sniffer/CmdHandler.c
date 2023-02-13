
#include "CmdHandler.h"

#include <stdio.h>

#include "ErrorHandler.h"

CmdHandler_status_t CmdHandler_ProcessCommand(CmdHandler_cmdCode_t command) {
    switch(command) {
        case CmdHandler_cmdCode_EXIT: {
            ErrorHandler_CleanExit();
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

    printf("\n");
}
