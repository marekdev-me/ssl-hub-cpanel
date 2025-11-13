Name: ssl-hub
Version: 1.0.0
Release: 1%{?dist}
Summary: SSL Hub — WHM plugin (AutoSSL + ZeroSSL via acme.sh)
License: MIT
URL: https://your.repo/ssl-hub
Source0: ssl-hub-%{version}.tar.gz
BuildArch: x86_64


%description
Go-based WHM CGI plugin that exposes AutoSSL controls and ZeroSSL issuance via acme.sh (dns_cpanel + cpanel_uapi).


%prep
%setup -q


%build
# Nothing to build here if shipping a prebuilt binary inside tarball under whm/cgi/ssl-hub


%install
mkdir -p %{buildroot}/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub
mkdir -p %{buildroot}/var/cpanel/apps
install -m 750 whm/cgi/ssl-hub %{buildroot}/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/ssl-hub
install -m 700 whm/cgi/zerossl.sh %{buildroot}/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh
install -m 644 whm/appconf/ssl-hub.conf %{buildroot}/var/cpanel/apps/ssl-hub.conf


%post
/usr/local/cpanel/bin/register_appconfig /var/cpanel/apps/ssl-hub.conf || true


%preun
if [ "$1" = 0 ]; then
/usr/local/cpanel/bin/unregister_appconfig ssl-hub.conf || true
fi


%files
/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/ssl-hub
/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh
/var/cpanel/apps/ssl-hub.conf


%changelog
* Thu Nov 13 2025 You <you@example.com> - 1.0.0-1
- Initial release