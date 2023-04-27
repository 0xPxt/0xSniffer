#ifndef CMD_HANDLER
#define CMD_HANDLER

typedef enum CmdHandler_cmdCode {
    CmdHandler_cmdCode_IDLE = 0,
    CmdHandler_cmdCode_EXIT = 1,
    CmdHandler_cmdCode_SAVE = 2
} CmdHandler_cmdCode_t;

typedef enum CmdHandler_status {
    CmdHandler_status_OK = 0,
    CmdHandler_status_UNKNOWN_COMMAND = -1
} CmdHandler_status_t;

extern CmdHandler_status_t CmdHandler_ProcessCommand(CmdHandler_cmdCode_t command);

extern void CmdHandler_PrintCommandList(void);

#endif // INPUT_HANDLER