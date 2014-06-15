###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.16 2010/06/14 12:50:57 j-nijhof Exp $
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

man_MANS = pam-script.7

moduledir = @libdir@
module_LTLIBRARIES = pam_script.la
pam_script_la_SOURCES = pam_script.c
pam_script_la_CFLAGS = $(AM_CFLAGS) -DPAM_SCRIPT_DIR="\"$(sysconfdir)\""
pam_script_la_LDFLAGS = -module -avoid-version

EXTRA_DIST=					\
	etc

dist-hook:
	-rm -rf `find $(distdir) -name CVS`

install-data-hook:
#	@echo === install-data-hook ===
	-rm $(DESTDIR)/$(libdir)/$(module_LTLIBRARIES)

install-exec-hook:
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -d $(DESTDIR)$(sysconfdir)/pam-script.d
	${INSTALL} -m 644 etc/README $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 755 etc/pam_script $(DESTDIR)$(sysconfdir)
	(cd $(DESTDIR)$(sysconfdir); \
		PAMSCRIPTDIR=. ./pam_script -x -s all pam_script)
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
	@echo "make maintainer-clean	- cleans even more"
	@echo ""
