###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.4 2007/08/27 22:28:21 rkowen Exp $
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
	debian

CL: rmChangeLog
	@echo "Updating ChangeLog"
	-@./cvs2cl.pl

rmChangeLog:
	-@rm -f ChangeLog

dist-hook:
	-rm -rf `find $(distdir) -name CVS`

help:
	@echo ""
	@echo "make		- compile sources to a shared library module"
	@echo "make all		- same as above"
	@echo "make install	- copy module and docs to destination"
	@echo "make clean	- cleans out most useless files"
	@echo "make distclean	- cleans & removes most made files"
	@echo "make CL		- remakes the ChangeLog from the CVS commits"
	@echo ""

