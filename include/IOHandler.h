#ifndef IO_HANDLER
#define IO_HANDLER

extern void IOHandler_RequestInterfaceSelection(void);

extern void IOHandler_CreateAndStartLogger(void);

extern void IOHandler_WriteToLogger(void *packet, unsigned long packetLength);

extern void IOHandler_RequestNewCommand(void);

extern void IOHandler_CleanUp(void);

#endif // IO_HANDLER