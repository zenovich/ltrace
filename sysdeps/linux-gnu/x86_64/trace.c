#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "common.h"
#include "ptrace.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

void
get_arch_dep(Process *proc) {
        proc_archdep *a;

	if (!proc->arch_ptr)
		proc->arch_ptr = (void *)malloc(sizeof(proc_archdep));

	a = (proc_archdep *) (proc->arch_ptr);
	a->valid = (ptrace(PTRACE_GETREGS, proc->pid, 0, &a->regs) >= 0);
	if (a->valid) {
		a->valid = (ptrace(PTRACE_GETFPREGS, proc->pid, 0, &a->fpregs) >= 0);
	}
	if (a->regs.cs == 0x23) {
		proc->mask_32bit = 1;
		proc->personality = 1;
	}
}

void
set_arch_dep(Process *proc)
{
	proc_archdep *a;

	a = (proc_archdep *) (proc->arch_ptr);
	if (!a || !a->valid)
		return;

	ptrace(PTRACE_SETREGS, proc->pid, 0, &a->regs);
	ptrace(PTRACE_GETFPREGS, proc->pid, 0, &a->fpregs);
}

/* Returns 1 if syscall, 2 if sysret, 0 otherwise.
 */
int
syscall_p(Process *proc, int status, int *sysnum) {
	if (WIFSTOPPED(status)
	    && WSTOPSIG(status) == (SIGTRAP | proc->tracesysgood)) {
		long int ret = ptrace(PTRACE_PEEKUSER, proc->pid, 8 * ORIG_RAX, 0);
		if (ret == -1 && errno)
			return -1;

		*sysnum = ret;
		if (proc->callstack_depth > 0 &&
				proc->callstack[proc->callstack_depth - 1].is_syscall &&
				proc->callstack[proc->callstack_depth - 1].c_un.syscall == *sysnum) {
			return 2;
		}

		if (*sysnum >= 0) {
			return 1;
		}
	}
	return 0;
}

static unsigned int
gimme_arg32(enum tof type, Process *proc, int arg_num) {
	proc_archdep *a = (proc_archdep *) proc->arch_ptr;

	if (arg_num == -1) {	/* return value */
		return a->regs.rax;
	}

	if (type == LT_TOF_FUNCTION || type == LT_TOF_FUNCTIONR) {
		return ptrace(PTRACE_PEEKTEXT, proc->pid,
			      proc->stack_pointer + 4 * (arg_num + 1), 0);
	} else if (type == LT_TOF_SYSCALL || type == LT_TOF_SYSCALLR) {
		switch (arg_num) {
		case 0:
			return a->regs.rbx;
		case 1:
			return a->regs.rcx;
		case 2:
			return a->regs.rdx;
		case 3:
			return a->regs.rsi;
		case 4:
			return a->regs.rdi;
		case 5:
			return a->regs.rbp;
		default:
			fprintf(stderr,
				"gimme_arg32 called with wrong arguments\n");
			exit(2);
		}
	}
	fprintf(stderr, "gimme_arg called with wrong arguments\n");
	exit(1);
}

static void
set_arg32(enum tof type, Process *proc, int arg_num, unsigned int value) {
	proc_archdep *a = (proc_archdep *) proc->arch_ptr;

	if (arg_num == -1) {	/* return value */
		a->regs.rax = value;
		return;
	}

	if (type == LT_TOF_FUNCTION || type == LT_TOF_FUNCTIONR) {
		ptrace(PTRACE_POKETEXT, proc->pid,
			      proc->stack_pointer + 4 * (arg_num + 1), &value);
		return;
	} else if (type == LT_TOF_SYSCALL || type == LT_TOF_SYSCALLR) {
		switch (arg_num) {
		case 0:
			a->regs.rbx = value;
			return;
		case 1:
			a->regs.rcx = value;
			return;
		case 2:
			a->regs.rdx = value;
			return;
		case 3:
			a->regs.rsi = value;
			return;
		case 4:
			a->regs.rdi = value;
			return;
		case 5:
			a->regs.rbp = value;
			return;
		default:
			fprintf(stderr,
				"set_arg32 called with wrong arguments\n");
			exit(2);
		}
	}
	fprintf(stderr, "set_arg called with wrong arguments\n");
	exit(1);
}
static long
gimme_arg_regset(Process *proc, int arg_num, arg_type_info *info,
                 struct user_regs_struct *regs,
		 struct user_fpregs_struct *fpregs)
{
        union {
		uint32_t sse[4];
		long lval;
		float fval;
		double dval;
	} cvt;

        if (info->type == ARGTYPE_FLOAT || info->type == ARGTYPE_DOUBLE) {
		memcpy(cvt.sse, fpregs->xmm_space + 4*arg_num,
		       sizeof(cvt.sse));
		return cvt.lval;
	}

	switch (arg_num) {
	case 0:
		return regs->rdi;
	case 1:
		return regs->rsi;
	case 2:
		return regs->rdx;
	case 3:
		return regs->rcx;
	case 4:
		return regs->r8;
	case 5:
		return regs->r9;
	default:
		return ptrace(PTRACE_PEEKTEXT, proc->pid,
			      proc->stack_pointer + 8 * (arg_num - 6 + 1), 0);
	}
}

static void
set_arg_regset(Process *proc, int arg_num, arg_type_info *info,
                 struct user_regs_struct *regs,
		 struct user_fpregs_struct *fpregs, long value)
{
        union {
		uint32_t sse[4];
		long lval;
		float fval;
		double dval;
	} cvt;

	cvt.lval = value;

        if (info->type == ARGTYPE_FLOAT || info->type == ARGTYPE_DOUBLE) {
		memcpy(fpregs->xmm_space + 4*arg_num, cvt.sse,
		       sizeof(cvt.sse));
		return;
	}

	switch (arg_num) {
	case 0:
		regs->rdi = value;
		break;
	case 1:
		regs->rsi = value;
		break;
	case 2:
		regs->rdx = value;
		break;
	case 3:
		regs->rcx = value;
		break;
	case 4:
		regs->r8 = value;
		break;
	case 5:
		regs->r9 = value;
		break;
	default:
		ptrace(PTRACE_POKETEXT, proc->pid,
		      proc->stack_pointer + 8 * (arg_num - 6 + 1), &value);
	}
}

static long
gimme_retval(Process *proc, int arg_num, arg_type_info *info,
             struct user_regs_struct *regs, struct user_fpregs_struct *fpregs)
{
	if (info->type == ARGTYPE_FLOAT || info->type == ARGTYPE_DOUBLE)
		return gimme_arg_regset(proc, 0, info, regs, fpregs);
	else
		return regs->rax;
}

static void
set_retval(Process *proc, int arg_num, arg_type_info *info,
             struct user_regs_struct *regs, struct user_fpregs_struct *fpregs, long value)
{
	if (info->type == ARGTYPE_FLOAT || info->type == ARGTYPE_DOUBLE)
		set_arg_regset(proc, 0, info, regs, fpregs, value);
	else
		regs->rax = value;
}

long
gimme_arg(enum tof type, Process *proc, int arg_num, arg_type_info *info) {
	if (proc->mask_32bit)
		return (unsigned int)gimme_arg32(type, proc, arg_num);

	proc_archdep *arch = (proc_archdep *)proc->arch_ptr;

	if (arch == NULL || !arch->valid)
		return -1;

	if (type == LT_TOF_FUNCTIONR) {
		if (arg_num == -1)
			return gimme_retval(proc, arg_num, info,
					    &arch->regs, &arch->fpregs);
		else {
			struct callstack_element *elem
				= proc->callstack + proc->callstack_depth - 1;
			callstack_achdep *csad = elem->arch_ptr;
			assert(csad != NULL);
			return gimme_arg_regset(proc, arg_num, info,
						&csad->regs_copy,
						&csad->fpregs_copy);
		}
	}
	else
		return gimme_arg_regset(proc, arg_num, info,
					&arch->regs, &arch->fpregs);
}

void
set_arg(enum tof type, Process *proc, int arg_num, arg_type_info *info, long value)
{
	if (proc->mask_32bit) {
		set_arg32(type, proc, arg_num, value);
		return;
	}

	proc_archdep *arch = (proc_archdep *)proc->arch_ptr;

	if (arch == NULL || !arch->valid)
		return;

	if (type == LT_TOF_FUNCTIONR) {
		if (arg_num == -1)
			return set_retval(proc, arg_num, info,
					  &arch->regs, &arch->fpregs, value);
		else {
			struct callstack_element *elem
				= proc->callstack + proc->callstack_depth - 1;
			callstack_achdep *csad = elem->arch_ptr;
			assert(csad != NULL);
			return set_arg_regset(proc, arg_num, info,
						  &csad->regs_copy,
						  &csad->fpregs_copy, value);
		}
	}
	else
		return set_arg_regset(proc, arg_num, info,
					&arch->regs, &arch->fpregs, value);
}

void
save_register_args(enum tof type, Process *proc)
{
	proc_archdep *arch = (proc_archdep *)proc->arch_ptr;
	if (arch == NULL || !arch->valid)
		return;

	callstack_achdep *csad = malloc(sizeof(*csad));
	memset(csad, 0, sizeof(*csad));
	memcpy(&csad->regs_copy, &arch->regs, sizeof(arch->regs));
	memcpy(&csad->fpregs_copy, &arch->fpregs, sizeof(arch->fpregs));

	proc->callstack[proc->callstack_depth - 1].arch_ptr = csad;
}
