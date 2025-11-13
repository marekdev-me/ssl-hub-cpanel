# SSL Hub for WHM/cPanel

This repository contains the WHM plugin and helper scripts that integrate ZeroSSL and Let’s Encrypt AutoSSL providers with cPanel/WHM servers.

## Prerequisites

* Root access to a WHM/cPanel server (AlmaLinux/RHEL/CentOS).
* Go 1.21+ for building the CGI binary.
* [`acme.sh`](https://github.com/acmesh-official/acme.sh) installed under the `root` account (the ZeroSSL helper expects `/root/.acme.sh/acme.sh`).

## Building the CGI binary

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ssl-hub ./whm/cgi
```

## Installing the plugin

1. Copy the compiled `ssl-hub` binary to the WHM CGI directory:
   ```bash
   install -m 750 -o root -g root ssl-hub /usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/ssl-hub
   ```
2. Copy the ZeroSSL helper script and ensure it is executable:
   ```bash
   install -m 750 -o root -g root whm/cgi/zerossl.sh /usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh
   ```
3. From WHM (as the `root` user), open **WHM » Plugins » SSL Hub**.

## Configuring ZeroSSL AutoSSL

1. Obtain ZeroSSL External Account Binding (EAB) credentials (KID + HMAC) from your ZeroSSL account.
2. In the **ZeroSSL AutoSSL** tab of the plugin UI, enter the KID and HMAC once and click **Save ZeroSSL credentials**.
   * Credentials are stored under `/root/.ssl-hub/` with `600` permissions.
3. Ensure `acme.sh` is installed for the `root` user and has the cPanel DNS + deploy hooks available (`dns_cpanel` and `cpanel_uapi`).
4. To issue a certificate for a single domain (including the wildcard), submit the domain in the form.
5. To run ZeroSSL AutoSSL for every active cPanel account, click **Run ZeroSSL AutoSSL for all cPanel accounts**.

## Let’s Encrypt AutoSSL shortcuts

The **AutoSSL (Let’s Encrypt)** tab exposes convenience actions for enabling the Let’s Encrypt provider and triggering AutoSSL across all accounts via the WHM API.

## Optional shared-secret gate

To restrict access when proxying the CGI, set an environment variable and matching secret file:

```bash
export SSL_HUB_SHARED_SECRET="your-random-secret"
echo "your-random-secret" > /root/.ssl-hub/secret
chmod 600 /root/.ssl-hub/secret
```

When configured, the CGI compares the value using a constant-time check before running any actions.

