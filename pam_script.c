/*
 *  Written by Jeroen Nijhof <jeroen@jeroennijhof.nl> 2005/03/01
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program - see the file COPYING.
 */

/* --- includes --- */
#include <stdio.h>
#include <stdarg.h>			/* varg... */
#include <string.h>			/* strcmp,strncpy,... */
#include <sys/types.h>			/* stat, fork, wait */
#include <sys/stat.h>			/* stat */
#include <sys/wait.h>			/* wait */
#include <unistd.h>			/* stat, fork, execve, **environ */
#include <stdlib.h>			/* calloc, setenv, putenv */
#include <errno.h>			/* errno */
#include <signal.h>			/* signal, SIGCHLD, SIG_DFL, SIG_ERR */

/* enable these module-types */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>		/* pam_* */
#include <security/pam_modules.h>
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#if HAVE_VSYSLOG
#  include <syslog.h>			/* vsyslog */
#endif

/* --- customize these defines --- */

#ifndef PAM_SCRIPT_DIR
#  define PAM_SCRIPT_DIR	"/usr/bin"
#endif
#define PAM_SCRIPT_AUTH		"pam_script_auth"
#define PAM_SCRIPT_ACCT		"pam_script_acct"
#define PAM_SCRIPT_PASSWD	"pam_script_passwd"
#define PAM_SCRIPT_SES_OPEN	"pam_script_ses_open"
#define PAM_SCRIPT_SES_CLOSE	"pam_script_ses_close"

/* --- defines --- */

#define PAM_EXTERN	extern
#define BUFSIZE	128
#define DEFAULT_USER "nobody"

/* --- macros --- */
#define PAM_SCRIPT_SETENV(key)						\
	{if (pam_get_item(pamh, key, &envval) == PAM_SUCCESS)		\
		pam_script_setenv(#key, (const char *) envval);		\
	else	pam_script_setenv(#key, (const char *) NULL);}

/* external variables */
extern char **environ;

#if 0
/* convenient function to throw into one of the methods below
 * for setting as a breakpoint for debugging purposes.
 */
void pam_script_xxx(void) {
	int i = 1;
}
#endif

/* internal helper functions */

static void pam_script_syslog(int priority, const char *format, ...) {
	va_list args;
	va_start(args, format);

#if HAVE_VSYSLOG
	openlog(PACKAGE, LOG_CONS|LOG_PID, LOG_AUTH);
	vsyslog(priority, format, args);
	closelog();
#else
	vfprintf(stderr, format, args);
#endif
}

static void pam_script_setenv(const char *key, const char *value) {
#if HAVE_SETENV
	setenv(key, (value?value:""), 1);
#elif HAVE_PUTENV
	char	 buffer[BUFSIZE],
		*str;
	strncpy(buffer,key,BUFSIZE-2);
	strcat(buffer,"=");
	strncat(buffer,(value?value:""),BUFSIZE-strlen(buffer)-1);
	if ((str = (char *) malloc(strlen(buffer)+1)) != NULL) {
		strcpy(str,buffer);
		putenv(str);
	} /* else {
	     untrapped memory error - just do not add to environment
	} */
#else
#  error Can not set the environment
#endif
}

static int pam_script_get_user(pam_handle_t *pamh, const char **user) {
	int retval;

	retval = pam_get_user(pamh, user, NULL);
	if (retval != PAM_SUCCESS) {
		pam_script_syslog(LOG_ALERT, "pam_get_user returned error: %s",
			pam_strerror(pamh,retval));
		return retval;
	}
	if (*user == NULL || **user == '\0') {
		pam_script_syslog(LOG_ALERT, "username not known");
		retval = pam_set_item(pamh, PAM_USER,
			(const void *) DEFAULT_USER);
		if (retval != PAM_SUCCESS)
		return PAM_USER_UNKNOWN;
	}
	return retval;
}

static int pam_script_exec(pam_handle_t *pamh,
	const char *type, const char *script, const char *user,
	int rv, int argc, const char **argv) {

	int	retval = rv,
		status,
		i;
	char	cmd[BUFSIZE];
	char	**newargv;
	struct stat fs;
	const void *envval = NULL;
	pid_t	child_pid = 0;

	strncpy(cmd, PAM_SCRIPT_DIR, BUFSIZE - 1);

	/* check for pam.conf options */
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i],"onerr=",6)) {
			if (!strcmp(argv[i],"onerr=fail"))
				retval = rv;
			else if (!strcmp(argv[i],"onerr=success"))
				retval = PAM_SUCCESS;
			else
				pam_script_syslog(LOG_ERR,
					"invalid option: %s", argv[i]);
		}
		if (!strncmp(argv[i],"dir=",4)) {
			if (argv[i] + 4) { /* got new scriptdir */
				strncpy(cmd,argv[i] + 4, BUFSIZE - 2);
			}
		}
	}

	/* strip trailing '/' */
	if (cmd[strlen(cmd)-1] == '/') cmd[strlen(cmd)-1] = '\0';
	strcat(cmd,"/");
	strncat(cmd,script,BUFSIZE-strlen(cmd)-1);

	/* test for script existence first */
	if (stat(cmd, &fs) < 0) {
		/* stat failure */
		pam_script_syslog(LOG_ERR,"can not stat %s", cmd);
		return retval;
	}
	if ((fs.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))
	!= (S_IXUSR|S_IXGRP|S_IXOTH)) {
		/* script not executable at all levels */
		pam_script_syslog(LOG_ALERT,
			"script %s not fully executable", cmd);
		return retval;
	}

	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
		pam_script_syslog(LOG_WARNING,
			"cannot reset SIGCHLD handler to the default");

	/* Execute external program */
	/* fork process */
	switch(child_pid = fork()) {
	case -1:				/* fork failure */
		pam_script_syslog(LOG_ALERT,
			"script %s fork failure", cmd);
		return retval;
	case  0:				/* child */
		/* Get PAM environment, pass it onto the child's environment */
		PAM_SCRIPT_SETENV(PAM_SERVICE);
		pam_script_setenv("PAM_TYPE", type);
		pam_script_setenv("PAM_USER", user);
		PAM_SCRIPT_SETENV(PAM_RUSER);
		PAM_SCRIPT_SETENV(PAM_RHOST);
		PAM_SCRIPT_SETENV(PAM_TTY);
		PAM_SCRIPT_SETENV(PAM_AUTHTOK);
		PAM_SCRIPT_SETENV(PAM_OLDAUTHTOK);

		/* construct newargv */
		if (!(newargv = (char **) calloc(sizeof(char *), argc+2)))
			return retval;
		newargv[0] = cmd;
		for (i = 0; i < argc; i++) {
			newargv[1+i] = (char *) argv[i];
		}
		(void) execve(cmd, newargv, environ);
		/* shouldn't get here, unless an error */
		pam_script_syslog(LOG_ALERT,
			"script %s exec failure", cmd);
		return retval;

	default:				/* parent */
		if (waitpid(child_pid, &status, 0) == -1) {
			pam_script_syslog(LOG_ALERT,
				"error waiting for child %d: %s", child_pid, strerror(errno));
			return retval;
		}
		if (WIFEXITED(status))
			return (WEXITSTATUS(status) ? rv : PAM_SUCCESS);
		else
			return retval;
	}
	return PAM_SUCCESS;
}

static int pam_script_converse(pam_handle_t *pamh, int argc,
	struct pam_message **message, struct pam_response **response)
{
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(pamh, PAM_CONV, (const void **)(void *) &conv);
	if (retval == PAM_SUCCESS) {
		retval = conv->conv(argc, (const struct pam_message **) message,
				response, conv->appdata_ptr);
	}
	return retval;
}

static int pam_script_set_authtok(pam_handle_t *pamh, int flags,
	int argc, const char **argv, char *prompt, int authtok)
{
	int	retval;
	char	*password;
	
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *response;

	/* set up conversation call */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = prompt;
	response = NULL;

	if ((retval = pam_script_converse(pamh, 1, pmsg, &response)) != PAM_SUCCESS)
		return retval;

	if (response) {
		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && response[0].resp == NULL) {
			free(response);
			return PAM_AUTH_ERR;
		}
		password = response[0].resp;
	  	response[0].resp = NULL;
	} 
	else
		return PAM_CONV_ERR;

	free(response);
	pam_set_item(pamh, authtok, password);
	return PAM_SUCCESS;
}

static int pam_script_senderr(pam_handle_t *pamh, int flags,
	int argc, const char **argv, char *message)
{
	int retval;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *response;

	/* set up conversation call */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_ERROR_MSG;
	msg[0].msg = message;
	response = NULL;

	if ((retval = pam_script_converse(pamh, 1, pmsg, &response)) != PAM_SUCCESS)
		return retval;

	free(response);
	return PAM_SUCCESS;
}


/* --- authentication management functions --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	int retval;
	const char *user=NULL;
	char *password;

	if ((retval = pam_script_get_user(pamh, &user)) != PAM_SUCCESS)
		return retval;

	/*
	* Check if PAM_AUTHTOK is set by early pam modules and
	* if not ask user for password.
	*/
	pam_get_item(pamh, PAM_AUTHTOK, (void*) &password);

	if (!password) {
		retval = pam_script_set_authtok(pamh, flags, argc, argv, "Password: ", PAM_AUTHTOK);
		if (retval != PAM_SUCCESS) 
			return retval;
	}

	return pam_script_exec(pamh, "auth", PAM_SCRIPT_AUTH,
		user, PAM_AUTH_ERR, argc, argv);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
		   const char **argv)
{
	return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
	int retval;
	const char *user=NULL;

	if ((retval = pam_script_get_user(pamh, &user)) != PAM_SUCCESS)
		return retval;

	return pam_script_exec(pamh, "account", PAM_SCRIPT_ACCT,
		user,PAM_AUTH_ERR,argc,argv);
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
	int retval;
	const char *user = NULL;
	char *password = NULL;
        char new_password[BUFSIZE];

	if ((retval = pam_script_get_user(pamh, &user)) != PAM_SUCCESS)
		return retval;

	if ( flags & PAM_UPDATE_AUTHTOK ) {
		/*
		 * Check if PAM_OLDAUTHTOK is set by early pam modules and
		 * if not ask user (not root) for current password.
		 */
		pam_get_item(pamh, PAM_OLDAUTHTOK, (void*) &password);
		if (!password && strcmp(user, "root")) {
			retval = pam_script_set_authtok(pamh, flags, argc, argv, "Current password: ", PAM_OLDAUTHTOK);
			if (retval != PAM_SUCCESS)
				return retval;
			pam_get_item(pamh, PAM_OLDAUTHTOK, (void*) &password);
		}

		/*
		 * Check if PAM_AUTHTOK is set by early pam modules and 
		 * if not ask user for the new password.
		 */
		pam_get_item(pamh, PAM_AUTHTOK, (void*) &password);
		if (!password) {
			retval = pam_script_set_authtok(pamh, flags, argc, argv, "New password: ", PAM_AUTHTOK);
			if (retval != PAM_SUCCESS)
				return retval;
			pam_get_item(pamh, PAM_AUTHTOK, (void*) &password);
			strncpy(new_password, password, BUFSIZE);
			password = NULL;

			retval = pam_script_set_authtok(pamh, flags, argc, argv, "New password (again): ", PAM_AUTHTOK);
			if (retval != PAM_SUCCESS)
				return retval;
			pam_get_item(pamh, PAM_AUTHTOK, (void*) &password);

			/* Check if new password's are the same */
			if (strcmp(new_password, password)) {
				retval = pam_script_senderr(pamh, flags, argc, argv,
						"You must enter the same password twice.");
				if (retval != PAM_SUCCESS)
					return retval;
				return PAM_AUTHTOK_ERR;
			}
		}
		return pam_script_exec(pamh, "password", PAM_SCRIPT_PASSWD,
			user, PAM_AUTHTOK_ERR, argc, argv);
	}
	return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	int retval;
	const char *user = NULL;

	if ((retval = pam_script_get_user(pamh, &user)) != PAM_SUCCESS)
		return retval;

	return pam_script_exec(pamh, "session", PAM_SCRIPT_SES_OPEN,
		user, PAM_SESSION_ERR, argc, argv);
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
			 const char **argv)
{
	int retval;
	const char *user = NULL;

	if ((retval = pam_script_get_user(pamh, &user)) != PAM_SUCCESS)
		return retval;

	return pam_script_exec(pamh, "session", PAM_SCRIPT_SES_CLOSE,
		user, PAM_SESSION_ERR, argc, argv);
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_script_modstruct = {
	"pam_script",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif
