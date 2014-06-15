%global commit 33148ff1c207b05add7b7f6616d46029447e6766
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global _hardened_build 1
%global upstream_name pam-script

Name:           pam_script
Version:        1.1.7
Release:        2.git%{shortcommit}%{?dist}
Summary:        PAM module for executing scripts

Group:          Applications/System
License:        GPLv2
URL:            https://github.com/jeroennijhof/pam_script
Source0:        https://github.com/jeroennijhof/pam_script/archive/%{version}.tar.gz

%{?el5:BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)}

BuildRequires:  pam-devel 
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool

%description
pam_script allows you to execute scripts during authorization, password
changes and session openings or closings.

%prep
%setup -qn %{upstream_name}-%{version}

cp etc/README etc/README.module_types
autoreconf -vfi

%build
%configure --libdir=/%{_lib}/security
make %{?_smp_mflags}

cd -

%install
%{?el5:rm -rf %{buildroot}}
make install DESTDIR=%{buildroot}

rm %{buildroot}%{_sysconfdir}/README

%{?el5:%clean}
%{?el5:rm -rf %{buildroot}}

%posttrans
restorecon %{_sysconfdir}/pam_script*
restorecon %{_sysconfdir}/pam-script.d/

%files
%doc AUTHORS COPYING ChangeLog README NEWS etc/README.module_types etc/README.pam_script 
%dir %{_sysconfdir}/pam-script.d/
%{_sysconfdir}/pam_script*
/%{_lib}/security/*
%{_mandir}/man7/%{upstream_name}.7*

%changelog
* Wed Jun 11 2014 Jason Taylor <jason.taylor@secure-24.com> - 1.1.7-1
- Initial Build
