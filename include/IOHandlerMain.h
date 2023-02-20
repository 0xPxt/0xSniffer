#ifndef IO_HANDLER_MAIN
#define IO_HANDLER_MAIN

extern void IOHandlerMain_RequestInterfaceSelection(void);

extern void IOHandlerMain_CreateAndStartLogger(void);

extern void IOHandlerMain_WriteToLogger(void *packet, unsigned long packetLength);

extern void IOHandlerMain_RequestNewCommand(void);

extern void IOHandlerMain_CleanUp(void);

#endif // IO_HANDLER_MAIN