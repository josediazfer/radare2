/* radare2 - LGPL - Copyright 2015 pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#if __WINDOWS__
#include <windows.h>
#endif
#ifdef _MSC_VER
#include <process.h>
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len);
static int lang_pipe_file(RLang *lang, const char *file) {
	return lang_pipe_run (lang, file, -1);
}

#if __WINDOWS__
#define PIPE_BUF_SIZE 4096

static void pipe_close (LPTSTR pipe_path, PHANDLE h_pipe_p) {
	if (h_pipe_p && *h_pipe_p != INVALID_HANDLE_VALUE) {
		HANDLE h_pipe = *h_pipe_p;

		if (pipe_path) {
			DeleteFile (pipe_path);
		}
		CloseHandle (h_pipe);
		*h_pipe_p = INVALID_HANDLE_VALUE;
	}
}

static void proc_close (PHANDLE h_proc_p, PHANDLE h_th_p) {
	if (h_proc_p && *h_proc_p) {
		HANDLE h_proc = *h_proc_p;
		TerminateProcess (h_proc, 0);
		CloseHandle (h_proc);
		*h_proc_p = NULL;
	}
	if (h_th_p && *h_th_p) {
		HANDLE h_th = *h_th_p;
		CloseHandle (h_th);
		*h_th_p = NULL;
	}
}

static DWORD WINAPI wait_child_proc_cb(LPVOID params) {
	HANDLE h_proc = (HANDLE)((LPVOID *)params)[0];
	PHANDLE h_pipe_p = (PHANDLE)((LPVOID *)params)[1];
	LPTSTR pipe_path = (HANDLE)((LPVOID *)params)[2];
	bool *exit_pipe_run = (bool *)((LPVOID *)params)[3];

	WaitForSingleObject(h_proc, INFINITE);
	*exit_pipe_run = true;
	pipe_close (pipe_path, h_pipe_p);

	return 0;
}
static void lang_pipe_run_win(RLang *lang, HANDLE h_proc, HANDLE h_pipe, bool *exit_pipe_run) {
	CHAR buf[PIPE_BUF_SIZE];
	BOOL bSuccess = FALSE;
	int i, res = 0;
	DWORD dwRead, dwWritten;

	res = ConnectNamedPipe (h_pipe, NULL);
	if (!res) {
		if (!*exit_pipe_run) {
			r_sys_perror ("lang_pipe_run_win/ConnectNamedPipe");
		}
		return;
	}
	r_cons_break_push (NULL, NULL);
	do {
		if (r_cons_is_breaked ()) {
			break;
		}
		memset (buf, 0, PIPE_BUF_SIZE);
		bSuccess = ReadFile (h_pipe, buf, PIPE_BUF_SIZE, &dwRead, NULL);
		if (*exit_pipe_run)
			break;
		if (bSuccess && dwRead>0) {
			buf[sizeof (buf)-1] = 0;
			char *res = lang->cmd_str ((RCore*)lang->user, buf);
			if (res) {
				int res_len = strlen (res) + 1;
				for (i = 0; i < res_len; i++) {
					memset (buf, 0, PIPE_BUF_SIZE);
					dwWritten = 0;
					int writelen=res_len - i;
					int rc = WriteFile (h_pipe, res + i, writelen > PIPE_BUF_SIZE?PIPE_BUF_SIZE:writelen, &dwWritten, 0);
					if (*exit_pipe_run) {
						free (res);
						break;
					}
					if (!rc) {
						r_sys_perror ("lang_pipe_run_win/WriteFile");
					} else if (dwWritten > 0) {
						i += dwWritten - 1;
					}
				}
				free (res);
			} else {
				WriteFile (h_pipe, "", 1, &dwWritten, NULL);
			}
		}
	} while(!*exit_pipe_run);
	r_cons_break_pop ();
}
#else
static void env(const char *s, int f) {
	char *a = r_str_newf ("%d", f);
	r_sys_setenv (s, a);
//	eprintf ("%s %s\n", s, a);
	free (a);
}
#endif

static int lang_pipe_run(RLang *lang, const char *code, int len) {
#if __UNIX__
	int safe_in = dup (0);
	int child, ret;
	int input[2];
	int output[2];

	pipe (input);
	pipe (output);

	env ("R2PIPE_IN", input[0]);
	env ("R2PIPE_OUT", output[1]);

	child = r_sys_fork ();
	if (child == -1) {
		/* error */
	} else if (!child) {
		/* children */
		r_sandbox_system (code, 1);
		write (input[1], "", 1);
		close (input[0]);
		close (input[1]);
		close (output[0]);
		close (output[1]);
		exit (0);
		return false;
	} else {
		/* parent */
		char *res, buf[1024];
		/* Close pipe ends not required in the parent */
		close (output[1]);
		close (input[0]);
		r_cons_break_push (NULL, NULL);
		for (;;) {
			if (r_cons_is_breaked ()) {
				break;
			}
			memset (buf, 0, sizeof (buf));
			ret = read (output[0], buf, sizeof (buf)-1);
			if (ret < 1 || !buf[0]) {
				break;
			}
			buf[sizeof (buf) - 1] = 0;
			res = lang->cmd_str ((RCore*)lang->user, buf);
			//eprintf ("%d %s\n", ret, buf);
			if (res) {
				write (input[1], res, strlen (res)+1);
				free (res);
			} else {
				eprintf ("r_lang_pipe: NULL reply for (%s)\n", buf);
				write (input[1], "", 1); // NULL byte
			}
		}
		r_cons_break_pop ();
		/* workaround to avoid stdin closed */
		if (safe_in != -1) {
			close (safe_in);
		}
		safe_in = open (ttyname(0), O_RDONLY);
		if (safe_in != -1) {
			dup2 (safe_in, 0);
		} else {
			eprintf ("Cannot open ttyname(0) %s\n", ttyname(0));
		}
	}

	close (input[0]);
	close (input[1]);
	close (output[0]);
	close (output[1]);
	if (safe_in != -1) {
		close (safe_in);
	}
	waitpid (child, NULL, 0);
	return true;
#else
#if __WINDOWS__
	char *r2pipe_var = r_str_newf ("R2PIPE_IN%x", _getpid ());
	char *r2pipe_paz = r_str_newf ("\\\\.\\pipe\\%s", r2pipe_var);
	LPTSTR r2pipe_var_ = r_sys_conv_utf8_to_utf16 (r2pipe_var);
	LPTSTR r2pipe_paz_ = r_sys_conv_utf8_to_utf16 (r2pipe_paz);
	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	LPTSTR cmdline_ = NULL;
	LPVOID params[4];
	bool success = false;
	bool exit_pipe_run = false;
	HANDLE h_th = NULL, h_pipe = INVALID_HANDLE_VALUE;
	DWORD exit_code;

	si.cb = sizeof (STARTUPINFO);
	SetEnvironmentVariable (TEXT ("R2PIPE_PATH"), r2pipe_var_);
	h_pipe = CreateNamedPipe (r2pipe_paz_,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
			PIPE_BUF_SIZE,
			PIPE_BUF_SIZE,
			0, NULL);
	if (h_pipe == INVALID_HANDLE_VALUE) {
		r_sys_perror ("lang_pipe_run/CreateNamedPipe");
		goto err_lang_pipe_run;
	}
	cmdline_ = r_sys_conv_utf8_to_utf16 (code);
	if (!CreateProcess (NULL, cmdline_, NULL, NULL,
		TRUE, 0, NULL, NULL, &si, &pi)) {
		r_sys_perror ("lang_pipe_run/CreateProcess");
		goto err_lang_pipe_run;
	}
	/* a separate thread is created that sets exit_pipe_run once h_proc terminates. */
	params[0] = (LPVOID)pi.hProcess;
	params[1] = (LPVOID)&h_pipe;
	params[2] = (LPVOID)r2pipe_paz_;
	params[3] = (LPVOID)&exit_pipe_run;
	h_th = CreateThread (NULL, 0, wait_child_proc_cb, params, 0, NULL);
	if (!h_th) {
		r_sys_perror ("lang_pipe_run/CreateThread");
		goto err_lang_pipe_run;
	}
	/* lang_pipe_run_win has to run in the command thread to prevent deadlock. */
	lang_pipe_run_win (lang, pi.hProcess, h_pipe, &exit_pipe_run);

	/* wait for exit thread */
	if (GetExitCodeThread (h_th, &exit_code) && exit_code == STILL_ACTIVE) {
		proc_close (&pi.hProcess, &pi.hThread);
		WaitForSingleObject (h_th, INFINITE);
	}
	CloseHandle (h_th);
	success = true;
err_lang_pipe_run:
	pipe_close (r2pipe_paz_, &h_pipe);
	proc_close (&pi.hProcess, &pi.hThread);
	free (cmdline_);
	free (r2pipe_var);
	free (r2pipe_paz);
	free (r2pipe_var_);
	free (r2pipe_paz_);
	return success;
#endif
#endif
}

static struct r_lang_plugin_t r_lang_plugin_pipe = {
	.name = "pipe",
	.ext = "pipe",
	.license = "LGPL",
	.desc = "Use #!pipe node script.js",
	.run = lang_pipe_run,
	.run_file = (void*)lang_pipe_file,
};
