Name:       nagios-snmp
Version:    0.1
Release:	  1%{?dist}
Summary:    Highly-generalized Nagios plugin for SNMP checks	
Group:      System administration tools
License:    GPL
URL:	      https://gerrit.ccs.ornl.gov/#/admin/projects/nagios-snmp.rb	
Source0:    nagios-snmp.tar.gz	
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

Requires:   ruby rubygems rubygem-snmp	

%prep
%setup -q

%install
mkdir -p %{buildroot}/usr/bin
install --owner root --group root --mode 755 nagios-snmp.rb %{buildroot}/usr/bin
mkdir ${buildroot}/etc/nagios-snmp.rb.d

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/etc/nagios-snmp.rb.d
/usr/bin/nagios-snmp.rb
%doc README.md nagios_snmp.json_spec

%changelog
* Wed Feb 26 2014 Brian Lindblom <lindblombr@ornl.gov> 0.1
- Initial RPM
