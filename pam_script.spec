%global commit 1bb6718fa767107e97893c5fe538420ef249b0a0
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global _hardened_build 1
%global upstream_name pam-script

Name:           pam_script
Version:        1.1.8
Release:        1%{?dist}
Summary:        PAM module for executing scripts

Group:          Applications/System
License:        GPLv2+
URL:            https://github.com/jeroennijhof/pam_script
Source0:        https://github.com/jeroennijhof/pam_script/archive/%{commit}/pam_script-%{commit}.tar.gz

BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  pam-devel 
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool

%description
pam_script allows you to execute scripts during authorization, password
changes and session openings or closings.

%prep
%setup -qn %{name}-%{commit}

#generate our configure script
autoreconf -vfi

%build
%configure --libdir=/%{_lib}/security
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

rm %{buildroot}%{_sysconfdir}/README

%clean
rm -rf %{buildroot}

%files
%doc AUTHORS COPYING ChangeLog README NEWS etc/README.pam_script 
%config(noreplace) %dir %{_sysconfdir}/pam-script.d/
%config(noreplace) %{_sysconfdir}/pam_script*
/%{_lib}/security/*
%{_mandir}/man7/%{upstream_name}.7*

%changelog
* Fri Aug 19 2016 Jeroen Nijhof <jeroen@jeroennijhof.nl> - 1.1.8-1
- Fixed bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=817198

* Tue Jun 24 2014 Jason Taylor <jason.taylor@secure-24.com> - 1.1.7-1
- Initial Build
