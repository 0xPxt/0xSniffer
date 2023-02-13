
#include "IOHandler.h"

#include <stdio.h>

#include "InterfaceHandler.h"
#include "ErrorHandler.h"
#include "CmdHandler.h"
#include "LogUtils.h"

void IOHandler_RequestInterfaceSelection() {
    int selection;

    LogUtils_DisplayBanner();

    printf("Select the network interface you want to sniff:\n\n");

    InterfaceHandler_PrintInterfaces();

    printf("Enter the desired interface number and press ENTER: ");
    
    scanf("%d", &selection);

    while (InterfaceHandler_SelectInterface(selection) != InterfaceHandler_status_OK) {
        LogUtils_DisplayBanner();

        ErrorHandler_DisplayWarning("Invalid interface number, please choose a valid number");
        
        InterfaceHandler_PrintInterfaces();

        printf("Enter the desired interface number and press ENTER: ");
    
        scanf("%d", &selection);
    }

    printf("\nSuccess! You have selected: ");
    
    InterfaceHandler_PrintSelectedInterfaceInfo();
}

void IOHandler_RequestNewCommand() {
    int selection;

    LogUtils_DisplayBanner();

    printf("\nCurrently listening to: ");

    InterfaceHandler_PrintSelectedInterfaceInfo();

    printf("Select a new command:\n\n");

    CmdHandler_PrintCommandList();

    printf("Enter the desired command number and press ENTER: ");

    scanf("%d", &selection);

    while (CmdHandler_ProcessCommand(selection) != CmdHandler_status_OK) {
        LogUtils_DisplayBanner();

        ErrorHandler_DisplayWarning("Invalid command, please choose a valid number");
        
        CmdHandler_PrintCommandList();

        printf("Enter the desired command number and press ENTER: ");
    
        scanf("%d", &selection);
    }
}