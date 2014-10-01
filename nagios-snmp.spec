Name:       ruby-nagios-snmp
Version:    0.1
Release:	  1%{?dist}
BuildArch:  noarch
Summary:    Highly-generalized Nagios plugin for SNMP checks	
Group:      System administration tools
License:    GPL
URL:	      https://gerrit.ccs.ornl.gov/#/admin/projects/nagios-snmp.rb	
Source0:    ruby-nagios-snmp-%{version}.tar.gz	
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires:   ruby rubygems rubygem-snmp	

%description
This is a Nagios plugin designed to handle many SNMP monitoring use cases

%prep
%setup -q

%install
mkdir -p %{buildroot}/usr/bin
install nagios-snmp.rb %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/nagios-snmp.d

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/etc/nagios-snmp.d
/usr/bin/nagios-snmp.rb
%doc README.md nagios-snmp.json_spec

%changelog
* Wed Feb 26 2014 Brian Lindblom <lindblombr@ornl.gov> 0.1
- Initial RPM
