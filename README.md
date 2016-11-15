This is a step-by-step guide to configuring and managing a domain, remote server and hosted services, such as VPN, a private and obfuscated Tor bridge, and encrypted chat, using the [Debian GNU/Linux](https://www.debian.org/releases/jessie/amd64/ch01s03.html.en) operating system and other free software.

I like to set up my servers and services in these ways. This guide is **not** meant to be a canonical guide on best practices. I am **not** responsible for anything you do nor break by following any of these steps.

This guide is written for [Google Compute Engine](https://cloud.google.com/compute/) (GCE), but will very likely work well on other service providers, such as Linode or Amazon AWS, or any computer which will run GNU/Linux, such as an [APU1C](http://www.pcengines.ch/apu1c.htm) in a closet. It uses recommended configuration files from [drduh/config](https://github.com/drduh/config).

If you have a suggestion or spot an error, don't hack me, rather please send a [pull request](https://github.com/drduh/Debian-Privacy-Server-Guide/pulls) or [open an issue](https://github.com/drduh/Debian-Privacy-Server-Guide/issues/new) on GitHub.

- [Domain](#domain)
- [Compute Engine](#compute-engine)
  - [Create instance](#create-instance)
  - [Setup access](#setup-access)
  - [Connect](#connect)
  - [Apply updates](#apply-updates)
  - [Configure passwords](#configure-passwords)
  - [Configure instance](#configure-instance)
    - [tmux](#tmux)
    - [Zsh](#zsh)
    - [Vim](#vim)
    - [SSH](#ssh)
    - [GPG](#gpg)
- [Services](#services)
  - [Dnsmasq](#dnsmasq)
  - [DNSCrypt](#dnscrypt)
  - [Privoxy](#privoxy)
  - [Tor](#tor)
    - [Obfuscation](#obfuscation)
    - [Hidden Service](#hidden-service)
  - [Certificates](#certificates)
  - [OpenVPN](#openvpn)
  - [Web Server](#web-server)
  - [XMPP](#xmpp)
    - [Federating](#federating)
- [Mail](#mail)
- [Conclusion](#conclusion)
- [Todo](#todo)

# Domain

If you are not sure what a domain name is, see the [Wikipedia article](https://en.wikipedia.org/wiki/Domain_name) and decide if you would like to create one at all.

I had decided to purchase [duh.to](http://duh.to/) from [Tonic](https://www.tonic.to/), a `.to` top level domain registrar. A 5 year registration cost $200 - a steep price, but not unreasonable for an esoteric [ccTLD](https://en.wikipedia.org/wiki/.to) with many available short, memorable, three-letter domain names. Tonic.to also does not maintain [a public whois database](https://www.tonic.to/faq.htm#16), which is a privacy advantage.

You could instead purchase a less expensive `.com`, `.net` or any available domain name from a variety of TLDs and registrars, though be aware of not all offer [domain privacy](https://en.wikipedia.org/wiki/Domain_privacy), for instance the `.us` ccTLD.

After purchasing your domain, configure DNS settings. To use [Google Cloud DNS](https://cloud.google.com/dns/overview) with Tonic:

<img width="500" src="https://cloud.githubusercontent.com/assets/12475110/15527061/8a3ea228-2226-11e6-8970-8178f85af159.png">

Wait for DNS records to propagate, which may take several hours. While you wait, feel free to learn more about [Tonga](https://www.washingtonpost.com/archive/business/1997/07/01/tiny-tonga-expands-its-domain/40ad136f-6379-4c6c-b472-fed52378ba35/).

Eventually, a [WHOIS lookup](https://whois.icann.org/en/technical-overview) will return the [NS record](https://support.dnsimple.com/articles/ns-record/) of your hosting provider:

    $ whois duh.to
    Tonic whoisd V1.1
    duh ns-cloud-c1.googledomains.com
    duh ns-cloud-c2.googledomains.com

If it doesn't look right, log in to Tonic or your registrar and update DNS information accordingly.

# Compute Engine

## Create instance

**Optional** You may want to first [Create a network](https://console.cloud.google.com/networking/networks/add) to define firewall rules later, else the default rule set will be used.

Go to [VM instances](https://console.cloud.google.com/compute/instances) and select **Create Instance**.

Pick a name, zone and machine type. A standard "1 vCPU" or shared core "f1-micro" or "g1-small" machine with *Debian 8* are fine defaults:

<img width="400" src="https://cloud.githubusercontent.com/assets/12475110/15526750/bebb0ddc-2223-11e6-8be5-fc8af25bfe77.png">

A Service account is not necessary and can be disabled. Select **Create** to start the instance.

After a minute or so, once you have an *External IP* assigned, go to Networking > [Cloud DNS](https://console.cloud.google.com/networking/dns/zones) and select **Create Zone** to create a new DNS zone.

Create an [A record](https://support.dnsimple.com/articles/a-record/) for the domain by selecting **Add Record Set**:

<img width="400" src="https://cloud.githubusercontent.com/assets/12475110/15527304/b8d7e7dc-2228-11e6-82e1-cecfef097c4a.png">

Select **Create**.

After a short while, verify an *A record* is returned with the correct IPv4 address for your VM instance:

    $ dig +short a duh.to
    104.197.215.107

If it doesn't work, wait longer for records to propagate, or try specifying the registrar's name severs:

    $ dig +short a duh.to @ns-cloud-c1.googledomains.com
    104.197.215.107

Likewise, there should be [SOA records](https://support.dnsimple.com/articles/soa-record/):

    $ dig +short soa duh.to
    ns-cloud-c1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 1209600 300

## Setup access

Create a new, [4096-bit](http://danielpocock.com/rsa-key-sizes-2048-or-4096-bits) [RSA](https://utcc.utoronto.ca/~cks/space/blog/sysadmin/SSHKeyTypes) key-pair to use for logging into your instance via SSH (pass-phrase is optional):

    $ ssh-keygen -t rsa -b 4096 -C 'sysadm' -f ~/.ssh/duh

Where `sysadm` is the desired username on the instance.

Copy the public key:

    $ cat ~/.ssh/duh.pub
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/[...] sysadm

Edit your VM instance settings to paste the public key into the SSH Keys section:

<img width="400" alt="Adding an SSH key to an instance" src="https://cloud.githubusercontent.com/assets/12475110/15527491/796d1282-222a-11e6-95a2-db73a4b5a22b.png">

Select **Save**.

## Connect

On a client, edit `~/.ssh/config` to [use](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) the new key:

    Host duh
      User sysadm
      HostName duh.to
      IdentityFile ~/.ssh/duh

The first time you connect, you will see a [warning](https://superuser.com/questions/421074/ssh-the-authenticity-of-host-host-cant-be-established) about the host authenticity:

    $ ssh duh
    [...]
    The authenticity of host 'duh' (104.197.215.107)' can't be established.
    ECDSA key fingerprint is d6:9a:...:1d:c1.
    Are you sure you want to continue connecting (yes/no)?

To verify this fingerprint, you will need to check the instance Serial Console output.

See [YubiKey Guide](https://github.com/drduh/YubiKey-Guide) to further secure SSH keys.

## Apply updates

[Become root](https://superuser.com/questions/306923/what-does-sudo-s-actually-do):

    $ sudo -s

Install any pending updates:

    # apt-get update && apt-get -y upgrade

Install any important software, for example:

    # apt-get -y install dnsutils whois git gcc autoconf make lsof curl tcpdump

## Configure passwords

Create a password for the user:

    $ passwd sysadm

If you wish to allow use of sudo without a password for [convenience](https://security.stackexchange.com/questions/45712/how-secure-is-nopasswd-in-passwordless-sudo-mode):

    $ echo "sysadm ALL=(ALL) NOPASSWD:ALL" | sudo tee --append /etc/sudoers

Press `Control-D` or type `exit` to logout as root and return to the regular user.

## Configure instance

### tmux

[tmux](https://tmux.github.io/) is a terminal multiplexer. This program will allow you to reconnect to a working terminal session on a remote computer.

    $ sudo apt-get -y install tmux

Edit the [configuration](http://www.hamvocke.com/blog/a-guide-to-customizing-your-tmux-conf/):

    $ vim ~/.tmux.conf
    
Or use my [configuration](https://github.com/drduh/config/blob/master/tmux.conf):

    $ curl -o ~/.tmux.conf https://raw.githubusercontent.com/drduh/config/master/tmux.conf

Run `tmux` and open a new tab with `` `-c `` or specified keyboard shortcut.

`` `-1 ``, `` `-2 ``, `` `-3 `` switch to windows 1, 2, 3, etc.

`` `-d `` will disconnect from Tmux so you can save your session and log out.

When you reconnect to your instance, simply type `tmux attach -t <session name>` to select a session to "attach" to (default name is "0"; use `` `-$ `` to rename).

### Zsh

[Z shell](http://www.zsh.org/) is an interactive login shell with many features and improvements over Bourne shell.

    $ sudo apt-get -y install zsh

Set login shell to zsh:

    $ sudo chsh -s /usr/bin/zsh sysadm

Edit the [configuration](https://stackoverflow.com/questions/171563/whats-in-your-zshrc):

    $ vim ~/.zshrc

Or use my [configuration](https://github.com/drduh/config/blob/master/zshrc):

    $ curl -o ~/.zshrc https://raw.githubusercontent.com/drduh/config/master/zshrc

Open a new tmux tab and run `zsh` or start a new `ssh` session to make sure the configuration is working to your liking.

### Vim

[Vim](http://www.vim.org/) is an excellent open source text editor. Run `vimtutor` if you have not used Vim before.

    $ sudo apt-get -y install vim

Edit the [configuration](https://stackoverflow.com/questions/164847/what-is-in-your-vimrc):

    $ vim ~/.vimrc

Or use my [configuration](https://github.com/drduh/config/blob/master/vimrc):

    $ curl -o ~/.vimrc https://raw.githubusercontent.com/drduh/config/master/vimrc

    $ mkdir -p ~/.vim/{swaps,backups,undo}

Try out Vim:

    $ vim ~/.vimrc

Use `:q` to quit `:w` to write (save) or `:x` for both.

### SSH

Take a few steps to harden remote access: declare which users are allowed to log in, change the default listening port and generate a new host key. There are many more in-depth guides online on securing SSH ([1](https://stribika.github.io/2015/01/04/secure-secure-shell.html), [2](https://feeding.cloud.geek.nz/posts/hardening-ssh-servers/), [3](https://wp.kjro.se/2013/09/06/hardening-your-ssh-server-opensshd_config/); these are just basic suggestions:

Create a new host key (do not use a pass-phrase - else you won't be able to reconnect remotely):

    $ ssh-keygen -t rsa -b 4096 -f ssh_host_key

Move it into place:

    $ sudo mv ssh_host_key{,.pub} /etc/ssh

Lock down permissions:

    $ sudo chown root:root /etc/ssh/ssh_host_key{,.pub}

Edit the ssh server [configuration](https://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5):

    $ sudo -E vim /etc/ssh/sshd_config

Or use my [configuration](https://github.com/drduh/config/blob/master/sshd_config):

    $ sudo curl -o /etc/ssh/sshd_config https://raw.githubusercontent.com/drduh/config/master/sshd_config

Update Networking firewall rules to allow the new ssh listening port (for example, my sshd configuration uses TCP port 2222).

Do not exit your current ssh session yet; first make sure you can still connect!

Restart ssh server:

    $ sudo service ssh restart

On a client, edit `~/.ssh/config` to make any modifications, for example by adding `Port 2222`:

    Host duh
      HostName duh.to
      User sysadm
      IdentityFile ~/.ssh/duh
      Port 2222

Start a new ssh session to confirm it still works, then exit the other session.

**Note** On older versions of OS X, the ssh client may be out of date and may not support newer cipher suites. Either upgrade it using Homebrew, or comment out related lines in the server configuration to connect.

If you had created a new host key, you'll be asked to verify the new RSA key fingerprint:

    $ ssh duh
    The authenticity of host '[104.197.215.107]:2222 ([104.197.215.107]:2222)' can't be established.
    RSA key fingerprint is 19:de:..:fe:58:3a.
    Are you sure you want to continue connecting (yes/no)? yes

Check the fingerprint on the server from your previous, existing session:

    $ ssh-keygen -lf /etc/ssh/ssh_host_key
    4096 19:de:..:fe:58:3a /etc/ssh/ssh_host_key.pub (RSA)

Start `tmux` or reconnect to an existing session.

### GPG

[GNU Privacy Guard](https://www.gnupg.org/) is used to verify signatures for downloaded software, encrypt and decrypt files, text, email, and much more.

    $ sudo apt-get -y install gnupg gnupg-curl

Edit the [configuration](https://help.riseup.net/en/security/message-security/openpgp/best-practices):

    $ mkdir ~/.gnupg

    $ vim ~/.gnupg/gpg.conf

Or use my [configuration](https://github.com/drduh/config/blob/master/gpg.conf):

    $ mkdir ~/.gnupg

    $ curl -o ~/.gnupg/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf

Install a [keyserver](https://sks-keyservers.net/overview-of-pools.php#pool_hkps) [CA certificate](https://sks-keyservers.net/verify_tls.php):

    $ sudo curl -o /etc/sks-keyservers.netCA.pem https://sks-keyservers.net/sks-keyservers.netCA.pem

To symmetrically encrypt a directory:

    $ tar zcvf - ~/backup | gpg -c > ~/backup-$(date +%F-%H%M).tar.gz.gpg

To decrypt:

    $ gpg -o ~/decrypted-backup.tar.gz -d backup-2016-01-01-0000.tar.gz.gpg && tar zxvf ~/decrypted-backup.tar.gz

See [YubiKey Guide](https://github.com/drduh/YubiKey-Guide) to learn more about using GPG.

# Services

## Dnsmasq

[Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) is a lightweight DNS and DHCP server with many [useful](http://www.cambus.net/nxdomain-hijacking-dnsmasq-to-the-rescue/) [features](http://www.g-loaded.eu/2010/09/18/caching-nameserver-using-dnsmasq/).

Install Dnsmasq:

    $ sudo apt-get -y install dnsmasq

Edit the [configuration](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html):

    $ sudo -E vim /etc/dnsmasq.conf

Or use my [configuration](https://github.com/drduh/config/blob/master/dnsmasq.conf):

    $ sudo curl -o /etc/dnsmasq.conf https://raw.githubusercontent.com/drduh/config/master/dnsmasq.conf

Pick an upstream name server. To use Google resolvers, add `server=169.254.169.254` to `/etc/dnsmasq.conf` or use a `resolv-file`:

    $ echo "nameserver 169.254.169.254" | sudo tee /etc/resolv.dnsmasq
    nameserver 169.254.169.254

Install a DNS [blacklist](https://en.wikipedia.org/wiki/Hosts_(file)) ([alternative method](https://debian-administration.org/article/535/Blocking_ad_servers_with_dnsmasq)), for example:

    $ sudo curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts -o /etc/blacklist

**Optional** Append additional lists, for example:

    $ curl https://raw.githubusercontent.com/jmdugan/blocklists/master/corporations/facebook/facebook.com | sudo tee --append /etc/blacklist

Sanity check:

    $ wc -l /etc/blacklist
    29247 /etc/blacklist

    $ grep -ve "^127.0.0.1\|^0.0.0.0\|^#" /etc/blacklist | uniq
    255.255.255.255 broadcasthost
    ::1 localhost
    fe80::1%lo0 localhost

Restart the service:

    $ sudo service dnsmasq restart

Check the log to make sure it is running:

    $ sudo tail -F /var/log/dnsmasq
    started, version 2.72 cachesize 2000
    IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect
    using nameserver 127.0.0.1#40
    reading /etc/resolv.dnsmasq
    using nameserver 169.254.169.254#53
    read /etc/hosts - 5 addresses
    read /etc/blacklist - 26995 addresses

If it fails to start, try running it manually:

    $ sudo dnsmasq -C /etc/dnsmasq.conf -d
    dnsmasq: started, version 2.72 cachesize 2000
    dnsmasq: compile time options: IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect
    dnsmasq: reading /etc/resolv.dnsmasq
    dnsmasq: using nameserver 169.254.169.254#53
    dnsmasq: read /etc/hosts - 5 addresses
    dnsmasq: read /etc/blacklist - 26995 addresses

Query locally for an *A record* to confirm dnsmasq is working:

    $ dig +short a google.to @127.0.0.1
    74.125.202.105
    74.125.202.103
    74.125.202.104
    74.125.202.99
    74.125.202.147
    74.125.202.106

Remember to remove the `log-queries` option from `/etc/dnsmasq.conf` to disable DNS request/answer logging.

## DNSCrypt

[DNSCrypt](https://dnscrypt.org/) software can be used as a server and client to encrypt DNS traffic.

> If you are running your own private or public recursive DNS server, adding support for the DNSCrypt protocol requires installing [DNSCrypt-Wrapper](https://github.com/Cofyc/dnscrypt-wrapper), the server-side DNSCrypt proxy.

To configure a private or public DNSCrypt server, first install [libsodium](https://github.com/jedisct1/libsodium) and [libevent](http://libevent.org/):

    $ sudo apt-get -y install libsodium-dev libevent-dev

Clone the DNSCrypt-Wrapper repository and install the software:

    $ git clone --recursive git://github.com/Cofyc/dnscrypt-wrapper.git

    $ cd dnscrypt-wrapper

    $ make configure

    $ ./configure

    $ sudo make install

Create keys and certificate (see usage instructions on [Cofyc/dnscrypt-wrapper](https://github.com/Cofyc/dnscrypt-wrapper) for details):

    $ mkdir ~/dnscrypt && cd ~/dnscrypt

    $ dnscrypt-wrapper --gen-provider-keypair
    Generate provider key pair... ok.
    [...]
    Keys are stored in public.key & secret.key.

    $ dnscrypt-wrapper --gen-crypt-keypair
    Generate crypt key pair... ok.
    Secret key stored in crypt_secret.key

    $ dnscrypt-wrapper --gen-crypt-keypair --crypt-secretkey-file=1.key
    Generate crypt key pair... ok.
    Secret key stored in 1.key

    $ dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=1.key --provider-cert-file=1.cert
    [20300] 01 May 00:00:00.000 [notice] [main.c:405] Generating pre-signed certificate.
    [20300] 01 May 00:00:00.000 [notice] [main.c:412] TXT record for signed-certificate:
    [...]

Print the public key fingerprint:

    $ dnscrypt-wrapper --show-provider-publickey-fingerprint --provider-publickey-file public.key
    Provider public key fingerprint : 390C:...:F93E

Start DNSCrypt server:

    $ sudo dnscrypt-wrapper \
        --resolver-address=127.0.0.1:53 --listen-address=0.0.0.0:5355 \
        --provider-name=2.dnscrypt-cert.duh.to \
        --crypt-secretkey-file=1.key --provider-cert-file=1.cert -V

**Note** The provider-name value is *not* encrypted during the connection handshake.

Update Networking firewall rules to allow the new dnscrypt listening port (in this example, UDP port 5355).

**Optional** Restrict the IP address or range of addresses which can access your VM instance to prevent abuse and [DNS attacks](http://resources.infosecinstitute.com/attacks-over-dns/).

To connect from a Mac or Linux client (using the Provider public key fingerprint from above):

    $ sudo dnscrypt-proxy \
      -a 127.0.0.1:40 -r 104.197.215.107:5355 \
      -k 390C:...:F93E -N 2.dnscrypt-cert.duh.to
    [NOTICE] Starting dnscrypt-proxy 1.6.0
    [INFO] Generating a new session key pair
    [INFO] Done
    [INFO] Server certificate #808441433 received
    [INFO] This certificate looks valid
    [INFO] Chosen certificate #808441433 is valid from [2016-05-08] to [2017-05-08]
    [INFO] Server key fingerprint is 9147:...:212E
    [NOTICE] Proxying from 127.0.0.1:40 to 104.197.215.107:5355

Outgoing DNS packets should be encrypted from the client. For example, take a packet capture while running `dig a google.to @127.0.0.1 -p 40` in another terminal:

    $ sudo tcpdump -As80 -tni eth0 "udp port 5355"
    listening on eth0, link-type EN10MB (Ethernet), capture size 80 bytes
    IP 10.8.4.2.55555 > 104.197.215.107:5355: UDP, length 512
    E...    ...@..a
    ..%h.x}._.......G.....%.....0......bOF.".#%...ZA.T...

    IP 104.197.215.107.5355 > 10.8.4.2.55555: UDP, length 304
    E..L.E..)...h.x}
    ..%..._.8..r6fnvWj84'TQ.&.. O....&..>
    .P|y.%.....
    ^C

Compare with querying [Google Public DNS](https://en.wikipedia.org/wiki/Google_Public_DNS) directly with `dig a google.to @8.8.8.8` while listening on UDP port 53:

    $ sudo tcpdump -As80 -tni eth0 "udp port 53"
    listening on eth0, link-type EN10MB (Ethernet), capture size 80 bytes
    IP 10.8.4.2.55555 > 8.8.8.8.53: 45279+ [1au] A? google.to. (38)
    E..B....@..l
    ..%.....t.5...|... .........google.to.......)........
    IP 8.8.8.8.53 > 10.8.4.2.55555: 45279 1/0/1 (54)
    E..R*...4.=.....
    ..%.5.t.>...............google.to..............+.
    ^C

Once DNSCrypt is configured on the client, configure `dnsmasq` or another DNS program on the client to use `127.0.0.1#40` as the upstream resolver.

## Privoxy

[Privoxy](https://www.privoxy.org/) is a non-caching web proxy with advanced filtering capabilities for enhancing privacy, modifying web page data and HTTP headers, controlling access, and removing ads and other obnoxious Internet junk.

Install Privoxy on the server:

    $ sudo apt-get -y install privoxy

Edit the [configuration](https://www.privoxy.org/faq/configuration.html):

    $ sudo -E vim /etc/privoxy/config

Or use my [configuration](https://github.com/drduh/config/blob/master/privoxy):

    $ sudo curl -o /etc/privoxy/config https://raw.githubusercontent.com/drduh/config/master/privoxy

Restart Privoxy:

    $ sudo service privoxy restart

Test Privoxy locally on the server:

    $ ALL_PROXY=127.0.0.1:8000 curl -I http://p.p/
    HTTP/1.1 200 OK
    Content-Length: 3312
    Content-Type: text/html
    Cache-Control: no-cache
    Date: Sun, 01 May 2016 00:00:00 GMT
    Last-Modified: Sun, 01 May 2016 00:00:00 GMT
    Expires: Sat, 17 Jun 2000 12:00:00 GMT
    Pragma: no-cache

Clients can use the remote proxy with [Secure Shell tunneling](https://en.wikipedia.org/wiki/Tunneling_protocol), also known as a ["poor man's VPN"](https://www.linuxjournal.com/content/ssh-tunneling-poor-techies-vpn) (**Note** `AllowTcpForwarding yes` must be enabled in `/etc/ssh/sshd_config` on the server to use these features, followed by `sudo service ssh restart`).

    $ ssh -NCL 5555:127.0.0.1:8000 duh

In another client terminal:

    $ ALL_PROXY='127.0.0.1:5555' curl https://icanhazip.com/
    104.197.215.107

Or to use ssh as a [SOCKS proxy](https://sanctum.geek.nz/arabesque/ssh-socks-and-curl/):

    $ ssh -NCD 7000 duh

In another client terminal:

    $ curl --proxy socks5h://127.0.0.1:7000 https://icanhazip.com/
    104.197.215.107


Watch Privoxy logs (you may wish to disable logging by removing `debug` lines in `/etc/privoxy/config`):

    $ sudo tail -F /var/log/privoxy/logfile

## Tor

[Tor](https://www.torproject.org/) can be used as a public relay or as a [private bridge](https://www.torproject.org/docs/bridges.html.en) for you and your friends.

[Install Tor](https://www.torproject.org/docs/tor-relay-debian.html.en) on the server:

    $ sudo apt-get -y install tor

**Optional** Install and configure [anonymizing relay monitor (arm)](https://www.atagar.com/arm/), a terminal-based status monitor for Tor.

### Obfuscation

Additionally, obfuscate Tor traffic by using [obfsproxy](https://www.torproject.org/projects/obfsproxy.html.en) or some other [Tor pluggable transport](https://www.torproject.org/docs/pluggable-transports.html.en).

To install the latest version of obfs4proxy, first install [Golang](https://golang.org/):

    $ sudo apt-get -y install golang

Create a temporary download and build directory:

    $ export GOPATH=$(mktemp -d) ; echo $GOPATH
    /tmp/tmp.u40VUD66nP

[Download and build](https://golang.org/cmd/go/) [obfs4proxy](https://gitweb.torproject.org/pluggable-transports/obfs4.git):

    $ go get git.torproject.org/pluggable-transports/obfs4.git/obfs4proxy

Confirm it's built:

    $ $GOPATH/bin/obfs4proxy -version
    obfs4proxy-0.0.7-dev

Install it:

    $ sudo cp $GOPATH/bin/obfs4proxy /usr/local/bin

Secure it:

    $ sudo chown root:root /usr/local/bin/obfs4proxy

Edit `/etc/tor/torrc` to include:

    ORPort 9993
    ExtORPort auto
    BridgeRelay 1
    ServerTransportPlugin obfs4 exec /usr/local/bin/obfs4proxy
    ServerTransportListenAddr obfs4 0.0.0.0:10022

Restart Tor:

    $ sudo service tor restart

Ensure `obfs4proxy` is accepting connections:

    $ sudo lsof -Pni | grep 10022
    obfs4prox 6685     debiant-tor    4u  IPv6  44617      0t0  TCP *:10022 (LISTEN)

Update Networking firewall rules to allow the new proxy listening port (in this case, TCP port 10022).

If Tor did not start, try starting it manually (`sudo` may be required to bind to [privileged ports](https://www.w3.org/Daemon/User/Installation/PrivilegedPorts.html)):

    $ tor -f /etc/tor/torrc
    [notice] Opening Socks listener on 127.0.0.1:9050
    [notice] Opening OR listener on 0.0.0.0:9993
    [notice] Opening Extended OR listener on 127.0.0.1:0
    Extended OR listener listening on port 50161.
    [...]
    Bootstrapped 0%: Starting
    Bootstrapped 5%: Connecting to directory server
    Bootstrapped 45%: Asking for relay descriptors
    Bootstrapped 78%: Loading relay descriptors
    Registered server transport 'obfs4' at '[::]:10022'
    Guessed our IP address as 104.197.215.107 (source: 62.210.222.166).
    We now have enough directory information to build circuits.
    Bootstrapped 80%: Connecting to the Tor network
    Bootstrapped 90%: Establishing a Tor circuit
    Tor has successfully opened a circuit. Looks like client functionality is working.
    Bootstrapped 100%: Done

Copy the bridgeline, filling in the IP address and port:

    $ sudo tail -n1 /var/lib/tor/pt_state/obfs4_bridgeline.txt
    Bridge obfs4 <IP ADDRESS>:<PORT> <FINGERPRINT> cert=4ar[...]8FA iat-mode=0

To connect from a Mac or Linux client, edit `torrc` to use the IP address and assigned port, for example:

    UseBridges 1
    Bridge obfs4 104.197.215.107:10022 cert=4ar[...]8FA iat-mode=0

Using [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en), select Configure and Enter custom bridges:

<img width="500" src="https://cloud.githubusercontent.com/assets/12475110/15528945/844fe950-2238-11e6-8348-3084cf6341d9.png">

To connect from Android, download [Orbot](https://play.google.com/store/apps/details?id=org.torproject.android&hl=en) and [Orfox](https://play.google.com/store/apps/details?id=info.guardianproject.orfox&hl=en) applications and configure a custom bridge in Orbot settings.

### Hidden Service

**Optional** To host a [hidden service](https://www.torproject.org/docs/hidden-services.html.en), append something like this to `/etc/tor/torrc` on the server (for example, to use with a Web server):

    HiddenServiceDir /var/lib/tor/hidden_service/
    HiddenServicePort 80 127.0.0.1:80

Restart Tor:

    $ sudo service tor restart

Get the hidden service hostname:

    $ sudo cat /var/lib/tor/hidden_service/hostname
    pqccxgxxxxxxxl5h.onion

You can also host services like [ssh](https://tor.stackexchange.com/questions/123/how-can-i-anonymize-my-ssh-traffic-using-the-tor-network) as a hidden service.

To generate a specific .onion hostname, [some](https://security.stackexchange.com/questions/29772/how-do-you-get-a-specific-onion-address-for-your-hidden-service) [software](https://github.com/ReclaimYourPrivacy/eschalot) exists.

## Certificates

Create your own [public-key infrastructure](https://security.stackexchange.com/questions/87564/how-does-ssl-tls-pki-work), so that you may use your own keys and certificates for VPN, HTTPS, etc.

To create a certificate authority, intermediate authority, server and client certificates, download [my script](https://github.com/drduh/config/blob/master/pki.sh) (run on a trusted client machine, preferably [air-gapped](https://en.wikipedia.org/wiki/Air_gap_(networking))):

    $ mkdir ~/pki && cd ~/pki

    $ curl -o ~/pki/pki.sh https://raw.githubusercontent.com/drduh/config/master/pki.sh

Read through and edit the script and variables to your suit your needs:

    $ vim pki.sh

Make it executable:

    $ chmod +x pki.sh

Disable OpenSSL certificate requirements (e.g. must specify location):

    $ sudo sed -i.bak "s/= match/= optional/g" /usr/lib/ssl/openssl.cnf

Run the script, accepting prompts to sign certificates and commit changes:

    $ ./pki.sh

This will create private and public keys for a certificate authority, intemediate authority, server and one client:

    $ ls ~/pki
    ca.key      client.csr  demoCA            intermediate.pem  server.cnf  server.pem
    ca.pem      client.key  intermediate.csr  intermediate.srl  server.csr
    client.cnf  client.pem  intermediate.key  pki.sh            server.key

You could also use [OpenVPN/easy-rsa](https://github.com/OpenVPN/easy-rsa).

You could also purchase [trusted certificates](https://en.wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates) from a variety of online vendors. There are also [free](https://letsencrypt.org/) [options](https://www.startssl.com/Support?v=1) available from public certificate authorities. Use these if you can't install your own certificate authority on clients.

## OpenVPN

[OpenVPN](https://openvpn.net/index.php/open-source/downloads.html) is free, open source TLS-based VPN server and client software.

Install OpenVPN:

    $ sudo apt-get -y install openvpn

Edit the [configuration](https://openvpn.net/index.php/open-source/documentation/howto.html#server):

    $ sudo -E vim /etc/openvpn/openvpn.conf

Or use my [configuration](https://github.com/drduh/config/blob/master/openvpn.conf):

    $ sudo curl -o /etc/openvpn/openvpn.conf https://raw.githubusercontent.com/drduh/config/master/openvpn.conf

**Optional** Generate a [static key](https://openvpn.net/index.php/open-source/documentation/miscellaneous/78-static-key-mini-howto.html) so that only trusted clients can attempt connections (extra authentication on top of TLS):

    $ cd ~/pki

    $ openvpn --genkey --secret ta.key

Create [Diffie-Hellman key exchange parameters](https://security.stackexchange.com/questions/38206/can-someone-explain-a-little-better-what-exactly-is-accomplished-by-generation-o):

    $ cd ~/pki

    $ openssl dhparam -dsaparam -out dh.pem 2048

Configure certificates from the previous section, or install your own:

    $ sudo mkdir /etc/pki

    $ cd ~/pki

    $ cat ca.pem intermediate.pem > chain.pem

    $ sudo cp chain.pem server.pem server.key dh.pem ta.key /etc/pki

Enable [IP forwarding](https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux):

    $ sudo sysctl -w net.ipv4.ip_forward=1

To make the change permanent:

    $ echo "net.ipv4.ip_forward = 1" | sudo tee --append /etc/sysctl.conf

Create a [NAT](https://serverfault.com/questions/267286/openvpn-server-will-not-redirect-traffic/427756#427756) for VPN clients:

    $ sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.8.0.0/16 -j MASQUERADE

**Optional** Route all VPN Web (port 80) traffic through Privoxy (make sure it's configured to listen on that address, by adding `listen-address 10.8.0.1:8000` to `/etc/privoxy/config`).

    $ sudo iptables -t nat -A PREROUTING --source 10.8.0.0/16 -p tcp -m tcp --dport 80 -j DNAT --to 10.8.0.1:8000

To make it permanent:

    $ sudo apt-get -y install iptables-persistent

    $ sudo iptables-save | sudo tee /etc/iptables/rules.v4

If using Dnsmasq, add `listen-address=127.0.0.1,10.8.0.1` to `/etc/dnsmasq.conf`.

**Note** For some reason, IPv6 needs to be manually enabled on GCE first (I haven't figured this out yet, h/t to [this tip](https://ask.openstack.org/en/question/68190/how-do-i-resolve-rtnetlink-permission-denied-error-encountered-while-running-stacksh/)):

    $ sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0

To make it permanent:

    $ echo "net.ipv6.conf.all.disable_ipv6 = 0" | sudo tee --append /etc/sysctl.conf

Restart the service:

    $ sudo service openvpn restart

Watch the log:

    $ sudo tail -F /var/log/openvpn.log
    TUN/TAP device tun0 opened
    TUN/TAP TX queue length set to 100
    do_ifconfig, tt->ipv6=0, tt->did_ifconfig_ipv6_setup=0
    /sbin/ip link set dev tun0 up mtu 1500
    /sbin/ip addr add dev tun0 10.8.0.1/24 broadcast 10.8.0.255
    UDPv4 link local (bound): [undef]
    UDPv4 link remote: [undef]
    v=256
    IFCONFIG POOL: base=10.8.0.2 size=252, ipv6=0
    Initialization Sequence Completed

If it fails, try to start OpenVPN server manually:

    $ sudo openvpn --config /etc/openvpn/openvpn.conf --verb 3 --suppress-timestamps
    OpenVPN 2.3.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [MH] [IPv6] built on Nov 12 2015
    library versions: OpenSSL 1.0.1k 8 Jan 2015, LZO 2.08
    Diffie-Hellman initialized with 2048 bit key
    Control Channel Authentication: using '/etc/pki/ta.key' as a OpenVPN static key file
    Outgoing Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
    Incoming Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
    Socket Buffers: R=[212992->131072] S=[212992->131072]
    ROUTE_GATEWAY 10.240.0.1
    TUN/TAP device tun0 opened
    TUN/TAP TX queue length set to 100
    do_ifconfig, tt->ipv6=1, tt->did_ifconfig_ipv6_setup=1
    /sbin/ip link set dev tun0 up mtu 1500
    /sbin/ip addr add dev tun0 10.8.0.1/24 broadcast 10.8.0.255
    /sbin/ip -6 addr add 2001:db8:123::1/64 dev tun0
    [...]
    Initialization Sequence Completed

Update Networking firewall rules to allow the new VPN listening port (in this case, UDP port 443)

For each connecting device, edit a [client configuration](https://openvpn.net/index.php/open-source/documentation/howto.html#client):

    $ mkdir ~/vpn

    $ vim ~/vpn/client.ovpn

Or use my [configuration](https://github.com/drduh/config/blob/master/client.ovpn):

    $ curl -o ~/vpn/client.ovpn https://raw.githubusercontent.com/drduh/config/master/client.ovpn

Edit the configuration to define the server hostname. Insert `ca.pem`, `client.pem`, `client.key` contents in appropriate fields: *ca*, *cert* and *key*.

From a client, copy `ta.key` from your server:

    $ scp duh:~/pki/ta.key ~/vpn

To connect from Linux, install OpenVPN:

    $ sudo apt-get -y install openvpn

Start OpenVPN:

    $ cd ~/vpn

    $ sudo openvpn --config client.ovpn
    [...]
    TLS: Initial packet from [AF_INET]104.197.215.107:443, sid=6901c819 3e11276e
    VERIFY OK: depth=2, CN=Duh Authority
    VERIFY OK: depth=1, CN=Duh Intermediate Authority
    Validating certificate key usage
    ++ Certificate has key usage  00a0, expects 00a0
    VERIFY KU OK
    Validating certificate extended key usage
    ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
    VERIFY EKU OK
    VERIFY OK: depth=0, CN=duh.to
    [...]

Verify:

    $ curl https://icanhazip.com/
    104.197.215.107

To connect from Android, install [OpenVPN Connect](https://play.google.com/store/apps/details?id=net.openvpn.openvpn) from the Play Store.

Copy `client.ovpn` and `ta.key` to a folder on your device. They can just be downloaded from a Web browser.

Select **Import** > **Import Profile from SD card** and select `client.ovpn`, perhaps in the Download folder.

If the import was successful, select **Connect**.

To connect from a Mac, install OpenVPN from [Homebrew](https://github.com/drduh/OS-X-Security-and-Privacy-Guide#homebrew):

    $ brew install openvpn

Start OpenVPN:

    $ sudo ~/homebrew/sbin/openvpn --config client.ovpn
    OpenVPN 2.3.10 x86_64-apple-darwin15.2.0 [SSL (OpenSSL)] [LZO] [MH] [IPv6] built on Jan  6 2016
    [...]
    TLS: Initial packet from [AF_INET]104.197.215.107:443, sid=db4ecf82 4e4e4c5b
    VERIFY OK: depth=2, CN=Duh Authority
    VERIFY OK: depth=1, CN=Duh Intermediate Authority
    Validating certificate key usage
    ++ Certificate has key usage  00a0, expects 00a0
    VERIFY KU OK
    Validating certificate extended key usage
    ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
    VERIFY EKU OK
    VERIFY OK: depth=0, CN=duh.to
    [...]
    Initialization Sequence Completed

Verify:

    $ curl https://icanhazip.com/
    104.197.215.107

Or use a GUI-based VPN client like [Tunnelblick](https://tunnelblick.net/).

See also [OS-X-Security-and-Privacy-Guide#vpn](https://github.com/drduh/OS-X-Security-and-Privacy-Guide#vpn).

## Web Server

You may wish to run a Web server to serve static or dynamic pages.

Install [Lighttpd](https://www.lighttpd.net/) with [ModMagnet](http://redmine.lighttpd.net/projects/1/wiki/Docs_ModMagnet) (optional):

    $ sudo apt-get -y install lighttpd lighttpd-mod-magnet

Edit the [configuration](https://redmine.lighttpd.net/projects/1/wiki/TutorialConfiguration):

    $ sudo -E vim /etc/lighttpd/lighttpd.conf

Or use my [configuration](https://github.com/drduh/config/blob/master/lighttpd.conf):

    $ sudo curl -o /etc/lighttpd/lighttpd.conf https://raw.githubusercontent.com/drduh/config/master/lighttpd.conf

    $ sudo curl -o /etc/lighttpd/magnet.luau https://raw.githubusercontent.com/drduh/config/master/magnet.luau

**Note** Lighttpd expects the server private key and certificate to be stored in one file as the `ssl.pemfile` argument:

    $ cat /etc/pki/server.key /etc/pki/server.pem | sudo tee /etc/pki/lighttpd.pem

You may need to comment out the following line in `/etc/lighttpd/lighttpd.conf` in order to accept requests on Internet-facing interfaces:

    #server.bind = "127.0.0.1"

Restart Lighttpd:

    $ sudo service lighttpd restart

Check that it's running - look for the process listening on TCP ports 80 or 443:

    $ sudo lsof -Pni | grep lighttpd
    lighttpd  3291   www-data    4u  IPv4  18206      0t0  TCP *:80 (LISTEN)
    lighttpd  3291   www-data    5u  IPv4  18207      0t0  TCP *:443 (LISTEN)

If it failed to start, try running it directly to check for errors:

    $ sudo lighttpd -f /etc/lighttpd/lighttpd.conf -D

Update Networking firewall rules to allow the new HTTP/HTTPS listening port(s) (in this example, TCP port 80 and 443).

Create some content:

    $ echo "Hello, World" | sudo tee /var/www/index.html

Once Lighttpd is running, request a page from your server in a Web browser or by using cURL:

    $ curl -vv http://duh.to/
    Hello, World

You can use [client certificates](https://security.stackexchange.com/questions/14589/advantages-of-client-certificates-for-client-authentication) as a means of authentication and authorization, rather than relying on user-provided passwords. See my Lighttpd [configuration](https://github.com/drduh/config/blob/master/lighttpd.conf) for an example.

See also [ioerror/duraconf/configs/lighttpd/lighttpd.conf](https://github.com/ioerror/duraconf/blob/master/configs/lighttpd/lighttpd.conf).

## XMPP

Run your own [XMPP](https://en.wikipedia.org/wiki/XMPP) chat server with [Prosody](https://prosody.im/). Client can use [Off The Record (OTR) messaging](https://otr.cypherpunks.ca/), a form of secure messaging which includes encryption, authentication, deniability and perfect forward secrecy, to communicate privately.

Install Prosody:

    $ sudo apt-get -y install prosody

Edit the [configuration](https://prosody.im/doc/example_config):

    $ sudo -E vim /etc/prosody/prosody.cfg.lua

Or use my [configuration](https://github.com/drduh/config/blob/master/prosody.cfg.lua) and edit it to suit your needs:

    $ sudo curl -o /etc/prosody/prosody.cfg.lua https://raw.githubusercontent.com/drduh/config/master/prosody.cfg.lua

See also [Advanced ssl config](http://prosody.im/doc/advanced_ssl_config).

Use Diffie-Hellman key exchange parameters from the [Certificate](#certificates) steps:

    $ sudo cp ~/pki/dh.pem /etc/pki/dh.pem

Or create new parameters:

    $ sudo openssl dhparam -out /etc/pki/dh.pem 2048

Copy the server certificate and key from the [Certificate](#certificates) steps:

    $ sudo cp ~/pki/server.pem /etc/pki/xmpp-cert.pem

    $ sudo cp ~/pki/server.key /etc/pki/xmpp-key.pem

If using a custom CA or intermediate certificate, append it to the server certificate, for example:

    $ cd ~/pki && cat server.pem intermediate.pem ca.pem | sudo tee /etc/pki/xmpp-cert.pem

Or generate a new self-signed certificate:

    $ openssl req -x509 -newkey rsa:4096 -days 365 -sha256 -subj "/CN=duh.to" \
      -keyout /etc/pki/xmpp-key.pem -nodes -out /etc/pki/xmpp-cert.pem

Restart Prosody:

    $ sudo service prosody restart

Ensure it's running:

    $ sudo tail -n1 /var/log/prosody/prosody.log
    mod_posix       info    Successfully daemonized to PID 1831

Ensure it's listening:

    $ sudo lsof -Pni | grep prosody
    lua5.1     1831    prosody    6u  IPv6 317986      0t0  TCP *:5269 (LISTEN)
    lua5.1     1831    prosody    7u  IPv4 317987      0t0  TCP *:5269 (LISTEN)
    lua5.1     1831    prosody    8u  IPv6 317990      0t0  TCP *:5222 (LISTEN)
    lua5.1     1831    prosody    9u  IPv4 317991      0t0  TCP *:5222 (LISTEN)

Update Networking firewall rules to allow the new prosody listening ports (in this example, TCP ports 5222 and 5269).

Create a new user:

    $ sudo prosodyctl adduser doc@duh.to

**Note** The domain must match the server certificate common name (*CN_SERVER* in *pki.sh*) - check with `openssl x509 -in /etc/pki/xmpp-cert.pem -noout -subject`.

### Federating

**Optional** For other XMPP servers to communicate with yours, you must [configure DNS records](https://xmpp.org/rfcs/rfc6120.html#tcp-resolution-prefer) for [interdomain federation](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/im_presence/interdomain_federation):

`_xmpp-client._tcp` of type `SRV` with data `0 5 5222 duh.to.`

`_xmpp-server._tcp` of type `SRV` with data `0 5 5269 duh.to.`

After a little while, check your records:

    $ dig +short srv _xmpp-server._tcp.duh.to
    0 5 5269 duh.to.

    $ dig +short srv _xmpp-client._tcp.duh.to
    0 5 5222 duh.to.

To connect from a Linux client, use an XMPP client like [Profanity](http://profanity.im/) or [agl/xmpp-client](https://github.com/agl/xmpp-client):

    $ sudo apt-get -y install profanity

Start Profanity:

    $ profanity

Log in by typing `/connect doc@duh.to` and entering the password when prompted.

Generate OTR keys by typing `/otr gen` - this part may take a while.

Send a message to a contact by typing `/msg user@duh.to` - to navigate tabs, use `/win 1`, `/win 2`, etc.

To start OTR, type `/otr start` - Profanity will show *OTR session started (untrusted)*.

To authenticate your chat partner, type `/otr question foo? bar` where `bar` is an answer to `foo?` which only the person you assume to be speaking with can answer. If the person answers correctly, Profanity will show *Authentication successful* followed by *OTR session trusted* - now you can be sure the connection is encrypted and authenticated.

To connect from an Android client, use an XMPP client like [Conversations](https://conversations.im/) or [Chat Secure](https://play.google.com/store/apps/details?id=info.guardianproject.otr.app.im).

Start the app and sign in. If you receive a warning that the certificate is not signed by a known authority, verify it using the step below.

To start a chat, select the `+` icon and select *New Chat*.

Start OTR by selecting the lock icon and verifying your contact with a Q&A or out of band.

To connect from a Mac client, use an XMPP client like [Profanity](http://profanity.im/), [agl/xmpp-client](https://github.com/agl/xmpp-client), or [Adium](https://github.com/drduh/OS-X-Security-and-Privacy-Guide#otr).

If you can't connect, check for errors in `/var/log/prosody/prosody.err` on the server.

Verify the SHA-256 fingerprint matches the certificate you see on the server:

    $ openssl x509 -in /etc/pki/xmpp-cert.pem -fingerprint -noout -sha256

If it matches the fingerprint in the presented certificate prompt, trust it and connect.

# Mail

Configuring and running a mail server is an enormous [hassle](http://sealedabstract.com/code/nsa-proof-your-e-mail-in-2-hours/) and maintaining one is a [time-consuming task](https://www.digitalocean.com/community/tutorials/why-you-may-not-want-to-run-your-own-mail-server). Moreover, many service providers [do not allow](https://cloud.google.com/compute/docs/tutorials/sending-mail/) outbound SMTP.

It is much easier to simply run something like [Google Apps for Work](https://apps.google.com/) to get Gmail for your custom domain. If going down this route, simply follow instructions to configure MX records to point to Google's mail servers.

Visit [https://admin.google.com/](https://admin.google.com/) to get started. To verify your domain, simply download and host an HTML file or edit your DNS TXT records, per the instructions.

The [MX records](https://en.wikipedia.org/wiki/MX_record) for your domain should look something like this:

    $ dig mx +short duh.to
    1 aspmx.l.google.com.
    5 alt1.aspmx.l.google.com.
    5 alt2.aspmx.l.google.com.
    10 alt3.aspmx.l.google.com.
    10 alt4.aspmx.l.google.com.

**Warning** Google Apps appears to add *X-Originating-IP* headers to emails sent from newly registered domains. This may reveal information about the location and computer used to send your mail, so wait a little while (first *N* days? during *free trial* period?) before using Google Apps mail. Alternatively, only send mail from your instance by connecting through a proxy or using a text-based e-mail client, like [Mutt](http://www.mutt.org/).

To install Mutt:

    $ sudo apt-get -y install mutt

Edit the [configuration](http://muttrcbuilder.org/):

    $ vim ~/.muttrc

**Note** You will need to turn on 2-Step Verification and create an [App password](https://security.google.com/settings/security/apppasswords?pli=1) to use Mutt.

Lock it down:

    $ chmod 0600 ~/.muttrc

Start Mutt:

    $ mutt

Type `?` to see available commands, or read online guides to using Mutt.

# Conclusion

Reboot the instance and make sure everything still works. If not, you'll need to automate certain programs to start up on their own (for example, Privoxy will fail to start if OpenVPN does not first create a tunnel interface to bind to).

With this guide, one can set up a fairly secure server with several privacy- and security-enchancing services. The server can be used to circumvent firewalls, provide strong encryption and overall improve your online experience, all for a low monthly cost (average ~$30 per month for a Standard instance.) A domain name also lets you receive email and assign DNS records, which is convenient, but totally optional.

If you would like to test e-mail or XMPP, feel free to [contact me](http://duh.to/pub/):

    doc@duh.to

    PGP: 011C E16B D45B 27A5 5BA8 776D FF3E 7D88 647E BCDB
    OTR: 53E4 46FF 343D D8C1 F102 FA21 2588 1467 4FCF EEF0

# Todo

* Use [Cloud SDK](https://cloud.google.com/sdk/) command line tools for configuring VM instance
* Implement on a BSD
* Sandbox/harden programs
* Automate software updates
* Email alerts for low disk space, certificate expiry, etc.
