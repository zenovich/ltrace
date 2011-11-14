/* If the system headers did not provide the constants, hard-code the normal values. */
#ifndef __SYSDEPS_TRACE_H__
#define __SYSDEPS_TRACE_H__

#include "ptrace.h"
#include "common.h"

#ifndef PTRACE_EVENT_FORK
#warning  PTRACE_EVENT_FORK not found... redefining.
#define PTRACE_OLDSETOPTIONS    21
#define PTRACE_SETOPTIONS       0x4200
#define PTRACE_GETEVENTMSG      0x4201

/* options set using PTRACE_SETOPTIONS */
#define PTRACE_O_TRACESYSGOOD   0x00000001
#define PTRACE_O_TRACEFORK      0x00000002
#define PTRACE_O_TRACEVFORK     0x00000004
#define PTRACE_O_TRACECLONE     0x00000008
#define PTRACE_O_TRACEEXEC      0x00000010
#define PTRACE_O_TRACEVFORKDONE 0x00000020
#define PTRACE_O_TRACEEXIT      0x00000040

/* Wait extended result codes for the above trace options.  */
#define PTRACE_EVENT_FORK       1
#define PTRACE_EVENT_VFORK      2
#define PTRACE_EVENT_CLONE      3
#define PTRACE_EVENT_EXEC       4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT       6

#endif /* PTRACE_EVENT_FORK */
#endif /* __SYSDEPS_TRACE_H__ */
