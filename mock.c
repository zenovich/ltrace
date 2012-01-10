#include "config.h"

#ifdef HAVE_PYTHON
#include <Python.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"

#include "sys/ptrace.h"
#include "sys/time.h"
#include <stddef.h>

#ifdef HAVE_PYTHON
#include <Python.h>

static int
set_arg_into_python_tuple(enum tof type, Process *proc, int arg_num, arg_type_info * info, PyObject *pArgs);
static int
set_format_into_python_tuple(enum tof type, Process *proc, int arg_num, PyObject *pArgs);
static PyObject *
convert_value_to_python(enum tof type, Process *proc,
		long value, arg_type_info *info,
		void *st, arg_type_info* st_info);
static PyObject*
convert_string_to_python(enum tof type, Process *proc,
		void* addr, size_t maxlen);
static PyObject*
convert_bytes_to_python(enum tof type, Process *proc,
		void* addr, size_t maxlen);

#endif //HAVE_PYTHON

void
mock_return(enum tof type, Process *proc, char *function_name) {
	int replaced = 0;
	static arg_type_info infop = {.type=ARGTYPE_POINTER}, infoi = {.type=ARGTYPE_INT};
	struct opt_m_t *tmp = opt_m;
	while (tmp) {
		if (strcmp(tmp->name, function_name) == 0) {
			if (tmp->value) {
				int result = atoi(tmp->value);
				set_arg(type, proc, -1, &infoi, result);
				set_arch_dep(proc);
				++replaced;
			}
			break;
		}
		tmp = tmp->next;
	}

#ifdef HAVE_PYTHON
	Function *func = name2func(function_name);

	if (func && !replaced && opt_fake_return) {
		PyObject *pModule, *pFunc = NULL;
		PyObject *pArgs, *pValue;

		PyObject* sysmodules = PyImport_GetModuleDict();
		pModule = PyMapping_GetItemString(sysmodules, "__main__");

		if (pModule != NULL) {
			char *wrapper_name = malloc(strlen(function_name) + 9);
			if (!wrapper_name) {
				perror("ltrace: malloc");
				exit(1);
			}
			sprintf(wrapper_name, "%s_wrapper", function_name);
			if (PyObject_HasAttrString(pModule, wrapper_name))
				pFunc = PyObject_GetAttrString(pModule, wrapper_name);
			free(wrapper_name);
			/* pFunc is a new reference */
				if (pFunc && PyCallable_Check(pFunc)) {
				pArgs = PyTuple_New(func->num_params);
				int i;
				for (i = 0; i < func->num_params; i++) {
					i = set_arg_into_python_tuple(type, proc, i, func->arg_info[i], pArgs);
				}

				pValue = PyObject_CallObject(pFunc, pArgs);
				Py_DECREF(pArgs);
				if (pValue != NULL) {
					if (pValue != Py_None) {
						set_arg(type, proc, -1, func->return_info, PyLong_AsLong(pValue));
						set_arch_dep(proc);
					}
					Py_DECREF(pValue);
				}
				else {
					Py_DECREF(pFunc);
					Py_DECREF(pModule);
					PyErr_Print();
					fprintf(stderr,"Call failed\n");
					return;
				}
			}
			Py_XDECREF(pFunc);
			Py_DECREF(pModule);
		}
		else {
			PyErr_Print();
			fprintf(stderr, "Failed to find module __main__\n");
			return;
		}
	}
#endif // HAVE_PYTHON

	if (opt_q) {
		static struct timespec first_real_time;
		static int first_real_time_set = 0;

		if (strcmp(function_name, "time") == 0 || strcmp(function_name, "gettimeofday") == 0
		    || strcmp(function_name, "clock_gettime") == 0) {
			if (!first_real_time_set) {
				clock_gettime(CLOCK_REALTIME, &first_real_time);
				first_real_time_set = 1;
			}

			struct timespec real_time;
			clock_gettime(CLOCK_REALTIME, &real_time);
			if (real_time.tv_nsec < first_real_time.tv_nsec) {
				real_time.tv_nsec = first_real_time.tv_nsec - real_time.tv_nsec;
				--(real_time.tv_sec);
			}
			else
				real_time.tv_nsec -= first_real_time.tv_nsec;

			real_time.tv_sec += opt_q_time - first_real_time.tv_sec;

			if (strcmp(function_name, "time") == 0) {
				void *addr = (void*) gimme_arg(LT_TOF_FUNCTION, proc, 0, &infop);
				time_t real_time_fake = real_time.tv_sec;
				if (addr)
					uunmovebytes(proc, addr, (void *) &real_time_fake, sizeof(time_t));
				set_arg(type, proc, -1, &infoi, real_time_fake);
				set_arch_dep(proc);
			} else if (strcmp(function_name, "gettimeofday") == 0) {
				void *addr = (void*)gimme_arg(LT_TOF_FUNCTION, proc, 0, &infop);
				if (addr) {
					struct timeval real_time_fake;
					real_time_fake.tv_sec = real_time.tv_sec;
					real_time_fake.tv_usec = real_time.tv_nsec / 1000;
					uunmovebytes(proc, addr, (void *) &real_time_fake, sizeof(struct timeval));
				}
			} else if (strcmp(function_name, "clock_gettime") == 0) {
				clockid_t type = (clockid_t) gimme_arg(LT_TOF_FUNCTION, proc, 0, &infoi);
				void *addr = (void *)gimme_arg(LT_TOF_FUNCTION, proc, 1, &infop);
				if (addr && type == CLOCK_REALTIME)
					uunmovebytes(proc, addr, (void *) &real_time, sizeof(struct timespec));
			}
		}
	}
}

#ifdef HAVE_PYTHON
static int
set_arg_into_python_tuple(enum tof type, Process *proc, int arg_num, arg_type_info * info, PyObject *pArgs) {
	long arg;

	if (info->type == ARGTYPE_VOID) {
		PyTuple_SetItem(pArgs, arg_num, Py_None);
	} else if (info->type == ARGTYPE_FORMAT) {
		arg_num = set_format_into_python_tuple(type, proc, arg_num, pArgs);
	} else {
		arg = gimme_arg(type, proc, arg_num, info);
		PyObject *pVal = convert_value_to_python(type, proc, arg, info, NULL, NULL);
		if (!pVal) {
			PyTuple_SetItem(pArgs, arg_num, Py_None);
		} else {
			PyTuple_SetItem(pArgs, arg_num, pVal);
		}
	}
	return arg_num;
}

static int
set_format_into_python_tuple(enum tof type, Process *proc, int arg_num, PyObject *pArgs) {
	void *addr;
	unsigned char *str1;
	int i;
	arg_type_info info;

	info.type = ARGTYPE_POINTER;
	addr = (void *)gimme_arg(type, proc, arg_num, &info);
	if (!addr) {
		PyTuple_SetItem(pArgs, arg_num, Py_None);
		return arg_num;
	}

	str1 = malloc(INT_MAX);
	if (!str1) {
		PyTuple_SetItem(pArgs, arg_num, Py_None);
		return arg_num;
	}

	int len = umovebytes(proc, addr, str1, INT_MAX - 2);

	PyObject *pystr;
	pystr = PyByteArray_FromStringAndSize(addr, len);
	if (!pystr) {
		free(str1);
		PyTuple_SetItem(pArgs, arg_num, Py_None);
		return arg_num;
	}
	PyTuple_SetItem(pArgs, arg_num, pystr);

	for (i = 0; str1[i]; i++) {
		if (str1[i] == '%') {
			int is_long = 0;
			while (1) {
				unsigned char c = str1[++i];
				if (c == '%') {
					break;
				} else if (!c) {
					break;
				} else if (strchr("lzZtj", c)) {
					is_long++;
					if (c == 'j')
						is_long++;
					if (is_long > 1
							&& (sizeof(long) < sizeof(long long)
								|| proc->mask_32bit)) {
						str1[i + 1] = '\0';
						break;
					}
				} else if (c == 'd' || c == 'i' || c == 'o' || c == 'x') {
					info.type = ARGTYPE_LONG;
					if (!is_long || proc->mask_32bit) {
						PyObject *pl = PyLong_FromLong((int)gimme_arg(type, proc, ++arg_num, &info));
						if (!pl) {
							PyTuple_SetItem(pArgs, arg_num, Py_None);
						} else {
							PyTuple_SetItem(pArgs, arg_num, pl);
						}
					} else {
						PyObject *pl = PyLong_FromLong(gimme_arg(type, proc, ++arg_num, &info));
						if (!pl) {
							PyTuple_SetItem(pArgs, arg_num, Py_None);
						} else {
							PyTuple_SetItem(pArgs, arg_num, pl);
						}
					}
					break;
				} else if (c == 'u') {
					info.type = ARGTYPE_LONG;
					if (!is_long || proc->mask_32bit) {
						PyObject *pl = PyLong_FromLong((int)gimme_arg(type, proc, ++arg_num, &info));
						if (!pl) {
							PyTuple_SetItem(pArgs, arg_num, Py_None);
						} else {
							PyTuple_SetItem(pArgs, arg_num, pl);
						}
					} else {
						PyObject *pl = PyLong_FromUnsignedLong(gimme_arg(type, proc, ++arg_num, &info));
						if (!pl) {
							PyTuple_SetItem(pArgs, arg_num, Py_None);
						} else {
							PyTuple_SetItem(pArgs, arg_num, pl);
						}
					}
					break;
				} else if (strchr("eEfFgGaACS", c)
						|| (is_long
							&& (c == 'c' || c == 's'))) {
					str1[i + 1] = '\0';
					break;
				} else if (c == 'c') {
					info.type = ARGTYPE_LONG;
					PyObject *pl = PyLong_FromLong((int)gimme_arg(type, proc, ++arg_num, &info));
					if (!pl) {
						PyTuple_SetItem(pArgs, arg_num, Py_None);
					} else {
						PyTuple_SetItem(pArgs, arg_num, pl);
					}
					break;
				} else if (c == 's') {
					info.type = ARGTYPE_POINTER;
					pystr = PyByteArray_FromStringAndSize((void *)gimme_arg(type, proc, ++arg_num, &info), INT_MAX - 2);
					if (!pystr) {
						PyTuple_SetItem(pArgs, arg_num, Py_None);
					} else {
						PyTuple_SetItem(pArgs, arg_num, pystr);
					}
					break;
				} else if (c == 'p' || c == 'n') {
					PyObject *pl = PyLong_FromUnsignedLong(gimme_arg(type, proc, ++arg_num, &info));
					if (!pl) {
						PyTuple_SetItem(pArgs, arg_num, Py_None);
					} else {
						PyTuple_SetItem(pArgs, arg_num, pl);
					}
					break;
				} else if (c == '*') {
					info.type = ARGTYPE_LONG;
					PyObject *pl = PyLong_FromLong((int)gimme_arg(type, proc, ++arg_num, &info));
					if (!pl) {
						PyTuple_SetItem(pArgs, arg_num, Py_None);
					} else {
						PyTuple_SetItem(pArgs, arg_num, pl);
					}
				}
			}
		}
	}
	free(str1);
	return arg_num;
}

/* Args:
   type - syscall or shared library function or memory
   proc - information about the traced process
   value - the value to display
   info - the description of the type to display
   st - if the current value is a struct member, the address of the struct
   st_info - type of the above struct

   Those last two parameters are used for structs containing arrays or
   strings whose length is given by another structure element.
 */
PyObject *
convert_value_to_python(enum tof type, Process *proc,
		long value, arg_type_info *info,
		void *st, arg_type_info* st_info) {

	switch (info->type) {
		case ARGTYPE_VOID:
			return Py_None;
		case ARGTYPE_INT:
			return PyLong_FromLong((int) value);
		case ARGTYPE_UINT:
		case ARGTYPE_OCTAL:
			return PyLong_FromLong((unsigned) value);
		case ARGTYPE_LONG:
			if (proc->mask_32bit)
				return PyLong_FromLong((int) value);
			else
				return PyLong_FromLong(value);
		case ARGTYPE_ULONG:
			if (proc->mask_32bit)
				return PyLong_FromLong((unsigned) value);
			else
				return PyLong_FromUnsignedLong((unsigned long) value);
		case ARGTYPE_CHAR:
			return PyLong_FromLong((char) value);
		case ARGTYPE_SHORT:
			return PyLong_FromLong((short) value);
		case ARGTYPE_USHORT:
			return PyLong_FromLong((unsigned short) value);
		case ARGTYPE_DOUBLE:
		case ARGTYPE_FLOAT: {
					    union { long l; float f; double d; } cvt;
					    cvt.l = value;
					    return PyFloat_FromDouble(cvt.d);
				    }
		case ARGTYPE_POINTER:
		case ARGTYPE_ADDR:
				    if (!value)
					    return Py_None;
				    else
					    return PyLong_FromUnsignedLong((unsigned long) value);
		case ARGTYPE_FORMAT:
				    fprintf(stderr, "Should never encounter a format anywhere but at the top level (for now?)\n");
				    exit(1);
		case ARGTYPE_STRING:
				    return convert_string_to_python(type, proc, (void*) value,
						    INT_MAX);
		case ARGTYPE_STRING_N:
				    return convert_string_to_python(type, proc, (void*) value,
						    get_length(type, proc,
							    info->u.string_n_info.size_spec, st, st_info));
		case ARGTYPE_BYTES:
				    return convert_bytes_to_python(type, proc, (void*) value,
						    INT_MAX);
		case ARGTYPE_BYTES_N:
				    return convert_bytes_to_python(type, proc, (void*) value,
						    get_length(type, proc,
							    info->u.string_n_info.size_spec, st, st_info));
		case ARGTYPE_ARRAY:
				    return Py_None;
		case ARGTYPE_ENUM:
				    return PyLong_FromLong((int) value);
		case ARGTYPE_STRUCT:
				    return Py_None;
		case ARGTYPE_UNKNOWN:
		default:
				    if (proc->mask_32bit)
					    return PyLong_FromLong((int) value);
				    else
					    return PyLong_FromLong(value);
	}
}

static PyObject*
convert_string_to_python(enum tof type, Process *proc, void *addr,
		size_t maxlength) {
	char *str1;

	if (!addr)
		return Py_None;

	str1 = malloc(maxlength + 3);
	if (!str1)
		return Py_None;

	int len = umovestr(proc, addr, maxlength, str1);
#if PY_MAJOR_VERSION >= 3
	PyObject *result = PyBytes_FromStringAndSize(str1, (Py_ssize_t) len);
#else
	PyObject *result = PyString_FromStringAndSize(str1, (Py_ssize_t) len);
#endif
	free(str1);
	if (!result)
		return Py_None;

	return result;
}

static PyObject*
convert_bytes_to_python(enum tof type, Process *proc, void *addr,
			size_t maxlength) {
	char *str1;

	if (!addr)
		return Py_None;

	str1 = malloc(maxlength + 3);
	if (!str1)
		return Py_None;

	int len = umovebytes(proc, addr, str1, maxlength);
	PyObject *result = PyByteArray_FromStringAndSize(str1, (Py_ssize_t) len);
	free(str1);
	if (!result)
		return Py_None;

	return result;
}
#endif // HAVE_PYTHON
