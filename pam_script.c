/*
 *  Written by Jeroen Nijhof <jnijhof@nijhofnet.nl> 2005/03/01
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
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifdef HAVE_CONFIG
#  include "config.h"
#endif

/* --- customize these defines --- */

#define PAM_SCRIPT_AUTH		"/pam_script_auth"
#define PAM_SCRIPT_PASSWD	"/pam_script_passwd"
#define PAM_SCRIPT_SES_OPEN	"/pam_script_ses_open"
#define PAM_SCRIPT_SES_CLOSE	"/pam_script_ses_close"

/* --- defines --- */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#define PAM_EXTERN	extern
#define BUFSIZE	128
#define DEFAULT_USER "nobody"



/* --- authentication management functions --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc
			,const char **argv)
{
    int retval;
    const char *user=NULL;
    char cmd[BUFSIZE];

    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS) {
	fprintf(stderr, "get user returned error: %s", pam_strerror(pamh,retval));
	return retval;
    }
    if (user == NULL || *user == '\0') {
	fprintf(stderr, "username not known");
	retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
	if (retval != PAM_SUCCESS)
	    return PAM_USER_UNKNOWN;
    }

    retval = pam_get_user(pamh, &user, NULL);
snprintf(cmd, BUFSIZE, "%s%s %s", PAM_SCRIPT_DIR,
	"$(PAM_SCRIPT_AUTH)", user);
    retval = system(cmd);
    if (retval) {
        user = NULL;
        return PAM_AUTH_ERR;
    }
    user = NULL;
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
		   ,const char **argv)
{
     return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
		     ,const char **argv)
{
     return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
		     ,const char **argv)
{
     int retval;
     const char *user = NULL;
     char cmd[BUFSIZE];

     retval = pam_get_user(pamh, &user, NULL);
     if (retval != PAM_SUCCESS) {
           fprintf(stderr, "get user returned error: %s", pam_strerror(pamh,retval));
           return retval;
     }
     if (user == NULL || *user == '\0') {
           fprintf(stderr, "username not known");
           retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
           if (retval != PAM_SUCCESS)
                  return PAM_USER_UNKNOWN;
     }

     if ( flags == PAM_UPDATE_AUTHTOK ) {
           snprintf(cmd, BUFSIZE, "%s%s %s", PAM_SCRIPT_DIR,
		PAM_SCRIPT_PASSWD, user);
           retval = system(cmd);
           if (retval) {
                  user = NULL;
                  return PAM_AUTHTOK_ERR;
           }
     }
     user = NULL;
     return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc
			,const char **argv)
{
     int retval;
     const char *user = NULL;
     char cmd[BUFSIZE];

     retval = pam_get_user(pamh, &user, NULL);
     if (retval != PAM_SUCCESS) {
           fprintf(stderr, "get user returned error: %s", pam_strerror(pamh,retval));
           return retval;
     }
     if (user == NULL || *user == '\0') {
           fprintf(stderr, "username not known");
           retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
           if (retval != PAM_SUCCESS)
                  return PAM_USER_UNKNOWN;
     }

     snprintf(cmd, BUFSIZE, "%s%s %s", PAM_SCRIPT_DIR,
	"$(PAM_SCRIPT_SES_OPEN)", user);
     retval = system(cmd);
     if (retval) {
          user = NULL;
          return PAM_SESSION_ERR;
     }
     user = NULL;
     return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
			 ,const char **argv)
{
     int retval;
     const char *user = NULL;
     char cmd[BUFSIZE];

     retval = pam_get_user(pamh, &user, NULL);
     if (retval != PAM_SUCCESS) {
           fprintf(stderr, "get user returned error: %s", pam_strerror(pamh,retval));
           return retval;
     }
     if (user == NULL || *user == '\0') {
           fprintf(stderr, "username not known");
           retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
           if (retval != PAM_SUCCESS)
                  return PAM_USER_UNKNOWN;
     }

     snprintf(cmd, BUFSIZE, "%s%s %s", PAM_SCRIPT_DIR,
	"$(PAM_SCRIPT_SES_CLOSE)", user);
     retval = system(cmd);
     if (retval) {
          user = NULL;
          return PAM_SESSION_ERR;
     }
     user = NULL;
     return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
    "pam_permit",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif
