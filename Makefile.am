###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.1 2007/08/17 21:29:06 rkowen Exp $
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

moduledir = @libdir@
module_LTLIBRARIES = pam_script.la
pam_script_la_SOURCES = pam_script.c
pam_script_la_CFLAGS = $(AM_CFLAGS)
pam_script_la_LDFLAGS = -module -avoid-version

CL: rmChangeLog
	@echo "Updating ChangeLog"
	-@./cvs2cl.pl

rmChangeLog:
	-@rm -f ChangeLog

help:
	@echo ""
	@echo "make		- compile sources to a shared library module"
	@echo "make all		- same as above"
	@echo "make install	- copy module and docs to destination"
	@echo "make clean	- cleans out most useless files"
	@echo "make distclean	- cleans & removes most made files"
	@echo "make CL		- remakes the ChangeLog from the CVS commits"
	@echo ""

