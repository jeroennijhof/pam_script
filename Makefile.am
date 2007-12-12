###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.11 2007/12/12 17:19:15 rkowen Exp $
## Created:     2002/06/14
##
###########################################################################
##
## run  automake to generate a Makefile.in
##      Makefile.am \
##      configure.ac >  Makefile.in
##      aclocal.m4  /
##

ACLOCAL_AMFLAGS= -I config

man_MANS = debian/pam-script.7

moduledir = @libdir@
module_LTLIBRARIES = pam_script.la
pam_script_la_SOURCES = pam_script.c
pam_script_la_CFLAGS = $(AM_CFLAGS) -DPAM_SCRIPT_DIR="\"$(sysconfdir)\""
pam_script_la_LDFLAGS = -module -avoid-version

EXTRA_DIST=					\
	pam-script.spec				\
	debian					\
	etc

CL: rmChangeLog
	@echo "Updating ChangeLog"
	-@./cvs2cl.pl

rmChangeLog:
	-@rm -f ChangeLog

dist-hook:
	-rm -rf `find $(distdir) -name CVS`

install-data-hook:
#	@echo === install-data-hook ===
	-rm $(DESTDIR)/$(libdir)/$(module_LTLIBRARIES)

install-exec-hook:
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 644 etc/README $(DESTDIR)$(sysconfdir)
#	@echo === install-exec-hook ===

install-examples:
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 644 etc/README.examples $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 755 etc/logscript $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 755 etc/tally $(DESTDIR)$(sysconfdir)

install-logger:
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 755 etc/logscript $(DESTDIR)$(sysconfdir)
	cd $(DESTDIR)$(sysconfdir) && \
	for f in pam_script_auth pam_script_acct pam_script_passwd \
	pam_script_ses_open pam_script_ses_close; do \
		test -e $$f || $(LN_S) logscript $$f; \
	done

install-tally:
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 755 etc/tally $(DESTDIR)$(sysconfdir)
	cd $(DESTDIR)$(sysconfdir) && \
	for f in pam_script_auth pam_script_acct ; do \
		test -e $$f || $(LN_S) tally $$f; \
	done

ftp-sourceforge: dist
	@echo "placing sourceforge.net files";
	/bin/sh ./.ftp.sf $(DISTNAME).tar.gz;

help:
	@echo ""
	@echo "make		- compile sources to a shared library module"
	@echo "make all		- same as above"
	@echo "make install	- copy module and docs to destination"
	@echo "make install-examples	- install all of the example scripts"
	@echo "make install-logger	- install the logger example scripts"
	@echo "make install-tally	- install the tally  example scripts"
	@echo "make clean	- cleans out most useless files"
	@echo "make disthelp	- extra help for developers"
	@echo ""

disthelp:
	@echo ""
	@echo "make dist	- creates distribution tarballs"
	@echo "make distclean	- cleans & removes most made files"
	@echo "make CL		- remakes the ChangeLog from the CVS commits"
	@echo "make ftp-sourceforge	- upload to sourceforge"
	@echo ""
