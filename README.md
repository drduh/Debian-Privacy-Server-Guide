This is a guide to configuring and managing a domain and remote host with services such as VPN, obfuscated Tor bridge, and encrypted chat, using the [Debian GNU/Linux](https://www.debian.org/releases/jessie/amd64/ch01s03.html.en) operating system and other free software.

This guide is written for [Google Compute Engine](https://cloud.google.com/compute/), but will very work with other providers, such as Linode or Amazon, or on any computer which will run GNU/Linux, such as a [PC Engines APU](https://www.pcengines.ch/apu2.htm) in a closet. This guide uses configuration files from [drduh/config](https://github.com/drduh/config).

# Domain name

If you are not sure what a domain name is, skip this section for now.

I had decided to purchase [duh.to](http://duh.to/) from [Tonic](https://www.tonic.to/), a `.to` top level domain registrar. A 5 year registration cost $200 - a steep price, but not unreasonable for an esoteric [ccTLD](https://en.wikipedia.org/wiki/.to) with many available short, memorable, three-letter domain names. Tonic.to also does not maintain [a public whois database](https://www.tonic.to/faq.htm#16), which is a privacy advantage.

You could instead purchase a less expensive `.com`, `.net` or any available domain name from a variety of TLDs and registrars, though be aware of not all offer [domain privacy](https://en.wikipedia.org/wiki/Domain_privacy), for instance the `.us` ccTLD.

After purchasing your domain, configure DNS settings. To use [Google Cloud DNS](https://cloud.google.com/dns/overview) with Tonic:

<img width="500" src="https://cloud.githubusercontent.com/assets/12475110/15527061/8a3ea228-2226-11e6-8970-8178f85af159.png">

Wait for DNS records to propagate, which may take several hours. While you wait, feel free to learn more about [Tonga](https://www.washingtonpost.com/archive/business/1997/07/01/tiny-tonga-expands-its-domain/40ad136f-6379-4c6c-b472-fed52378ba35/).

Eventually, a [WHOIS lookup](https://whois.icann.org/en/technical-overview) will return the [NS record](https://support.dnsimple.com/articles/ns-record/) of your hosting provider:

```console
$ whois duh.to
Tonic whoisd V1.1
duh ns-cloud-c1.googledomains.com
duh ns-cloud-c2.googledomains.com
```

If it doesn't look right, log in to Tonic or your registrar and update DNS information accordingly.

# Server setup

Download and configure the gcloud [command line tool](https://cloud.google.com/sdk/gcloud/).

Log in and enter the verification code, then create a project with any name:

```console
$ PROJECT=$(tr -dc '[:lower:]' < /dev/urandom | fold -w20 | head -n1)

$ gcloud auth login

$ gcloud projects create $PROJECT

$ gcloud config set project $PROJECT
```

Set the `INSTANCE`, `NETWORK`, [`TYPE`](https://cloud.google.com/compute/docs/machine-types), and [`ZONE`](https://cloud.google.com/compute/docs/regions-zones/) variables, as well as a recent `IMAGE`:

```console
$ INSTANCE=debian-privsec-standard
$ NETWORK=debian-privsec-net
$ TYPE=n1-standard-1
$ ZONE=us-east1-a
$ IMAGE=$(gcloud compute images list | grep debian | awk '{print $1}')
```

Create a new network:

```console
$ gcloud compute networks create $NETWORK
```

Create an instance:

```console
$ gcloud compute --project=$PROJECT instances create $INSTANCE --zone=$ZONE --subnet=$NETWORK \
  --machine-type=$TYPE --network-tier=PREMIUM --can-ip-forward --no-restart-on-failure --maintenance-policy=MIGRATE \
  --no-service-account --no-scopes --image=$IMAGE --image-project=debian-cloud \
  --boot-disk-size=40GB --boot-disk-type=pd-standard --boot-disk-device-name=$INSTANCE
```

You may need to set the billing account using the Web UI, enable the Compute API, wait several minutes, and then try again.

Add a firewall rule for remote access to your assigned netblock:

```console
$ gcloud compute firewall-rules create ssh-tcp-22 --network $NETWORK --allow tcp:22 --source-ranges $(whois $(curl -s https://icanhazip.com) | grep CIDR | awk '{print $2}')
```

## Update domain records

Once you have an *External IP* assigned, you may want to configure a DNS record. To do so, go to Networking > [Cloud DNS](https://console.cloud.google.com/networking/dns/zones) and select **Create Zone** to create a new DNS zone.

Create an [A record](https://support.dnsimple.com/articles/a-record/) for the domain by selecting **Add Record Set**:

<img width="400" src="https://cloud.githubusercontent.com/assets/12475110/15527304/b8d7e7dc-2228-11e6-82e1-cecfef097c4a.png">

Select **Create**.

After a short while, verify an *A record* is returned with the correct IPv4 address for the instance:

```console
$ dig +short a duh.to
104.197.215.107
```

If it doesn't work, wait longer for records to propagate, or try specifying the registrar's name severs:

```console
$ dig +short a duh.to @ns-cloud-c1.googledomains.com
104.197.215.107
```

Likewise, there should be [SOA records](https://support.dnsimple.com/articles/soa-record/):

```console
$ dig +short soa duh.to
ns-cloud-c1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 1209600 300
```

## Setup access

Use an existing [YubiKey](https://github.com/drduh/YubiKey-Guide#ssh):

```console
$ ssh-add -L
ssh-rsa AAAAB4NzaC1yc2EAAAADAQABAAACAz[...]zreOKM+HwpkHzcy9DQcVG2Nw== cardno:000605553211
```

Or create a new [4096-bit](https://danielpocock.com/rsa-key-sizes-2048-or-4096-bits) [RSA](https://utcc.utoronto.ca/~cks/space/blog/sysadmin/SSHKeyTypes) key-pair to use for logging into the instance via SSH:

```console
$ ssh-keygen -t rsa -b 4096 -C 'sysadm' -f ~/.ssh/duh
```

Where `sysadm` is the desired username on the instance.

Create a temporary file in [metadata format](https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys):

```console
$ echo -n "sysadm:" ; cat ~/.ssh/duh.pub > /tmp/ssh-public-key
sysadm:ssh-rsa AAAAB3Nza[...]
```

Update instance metadata:

```console
$ gcloud compute instances add-metadata debian-privsec-standard --metadata-from-file ssh-keys=/tmp/ssh-public-key
```

## Connect

On a client, edit `~/.ssh/config` to [use](https://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) the new key:

```
Host duh
  User sysadm
  HostName duh.to
  #HostName 104.197.215.107
  IdentityFile ~/.ssh/duh
```

The first time you connect, you will see a [warning](https://superuser.com/questions/421074/ssh-the-authenticity-of-host-host-cant-be-established) about the host authenticity:

```console
$ ssh duh
[...]
The authenticity of host 'duh' (104.197.215.107)' can't be established.
ECDSA key fingerprint is d6:9a:...:1d:c1.
Are you sure you want to continue connecting (yes/no)? yes
```

See [YubiKey Guide](https://github.com/drduh/YubiKey-Guide) to secure SSH keys.

## Apply updates

Install pending updates:

```console
$ sudo apt update && sudo apt upgrade -y
```

Install any necessary software, for example:

```console
$ sudo apt -y install \
  zsh vim tmux dnsutils whois \
  git gcc autoconf make \
  lsof tcpdump htop tree \
  apt-transport-https
```

## Configure instance

Clone the configuration repository:

```console
$ git clone https://github.com/drduh/config
```

### SSH

Take a few steps to harden remote access: declare which users are allowed to log in, change the default listening port and generate a new host key.

On a local machine (not the remote host), create new RSA keys (do not use a pass-phrase - else you won't be able to connect remotely after a reboot):

```console
$ cd /tmp

$ ssh-keygen -t rsa -b 4096 -f ssh_host_key -C '' -N ''

$ scp /tmp/ssh_host_key* duh:~
```

On the remote host, move the keys into place and lock down file permissions:

```console
$ sudo mv ssh_host_key ssh_host_key.pub /etc/ssh/

$ sudo chown root:root /etc/ssh/ssh_host_key /etc/ssh/ssh_host_key.pub

$ sudo chmod 0600 /etc/ssh/ssh_host_key
```

Use my [configuration](https://github.com/drduh/config/blob/master/sshd_config):

```console
$ sudo cp ~/config/sshd_config /etc/ssh/
```

Or [customize your own](https://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5).

Update firewall rules to allow the new SSH port:

```console
$ gcloud compute firewall-rules create ssh-tcp-2222 --network $NETWORK --allow tcp:2222 --source-ranges --source-ranges $(whois $(curl -s https://icanhazip.com) | grep CIDR | awk '{print $2}')
```

Do not exit the current SSH session yet; first make sure you can still connect!

Restart SSH server:

```console
$ sudo service ssh restart
```

On a client, edit `~/.ssh/config` to make any modifications, for example by adding `Port 2222`:

```
Host duh
  User sysadm
  HostName duh.to
  IdentityFile ~/.ssh/duh
  Port 2222
```

Start a new SSH session. Verify the new key fingerprint:

```console
$ ssh duh
The authenticity of host '[104.197.215.107]:2222 ([104.197.215.107]:2222)' can't be established.
RSA key fingerprint is 19:de:..:fe:58:3a.
Are you sure you want to continue connecting (yes/no)? yes
```

To check the SHA256 fingerprint of the host key from the established session:

```console
$ ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_key.pub
4096 SHA256:47DEQpj8HBSa+/TImW+6JCeuQfRkm5NMpJWZG3hSuFU no comment (RSA)
```

To check the MD5 fingerprint of the host key:

```console
$ ssh-keygen -E md5 -lf /etc/ssh/ssh_host_key.pub
4096 19:de:..:fe:58:3a /etc/ssh/ssh_host_key.pub (RSA)
```

If the fingerprint matches, exit the original SSH session.

### tmux

[tmux](https://tmux.github.io/) is a terminal multiplexer. This program allows reconnecting to a working terminal session on the instance.

Use my [configuration](https://github.com/drduh/config/blob/master/tmux.conf):

```console
$ cp ~/config/tmux.conf ~/.tmux.conf
```

Or [customize your own](https://www.hamvocke.com/blog/a-guide-to-customizing-your-tmux-conf/).

Run `tmux` and open a new tab with `` `-c `` or specified keyboard shortcut.

`` `-1 ``, `` `-2 ``, `` `-3 `` switch to windows 1, 2, 3, etc.

`` `-d `` will disconnect from Tmux so you can save the session and log out.

When you reconnect to the instance, type `tmux attach -t <session name>` (or `tmux a` for short) to select a session to "attach" to (default name is "0"; use `` `-$ `` to rename).

**Note** If you're using the st terminal and receive the error `open terminal failed: missing or unsuitable terminal: st-256color`, copy the file `st.info` from st's build directory to the instance and run `tic st.info`.

### Zsh

[Z shell](https://www.zsh.org/) is an interactive login shell with many features and improvements over Bourne shell.

To set the login shell for the current user to Zsh:

```console
$ sudo chsh -s /usr/bin/zsh $USER
```

Use my [configuration](https://github.com/drduh/config/blob/master/zshrc):

```console
$ cp ~/config/zshrc .zshrc
```

Or [customize your own](https://stackoverflow.com/questions/171563/whats-in-your-zshrc).

Open a new tmux tab and run `zsh` or start a new `ssh` session to make sure the configuration is working to your liking.

### Vim

[Vim](http://www.vim.org/) is an excellent open source text editor. Run `vimtutor` if you have not used Vim before.

Use my [configuration](https://github.com/drduh/config/blob/master/vimrc):

```console
$ cp ~/config/vimrc .vimrc

$ mkdir -p ~/.vim/{backup,swap,undo}
```

Or [customize your own vimrc](https://stackoverflow.com/questions/164847/what-is-in-your-vimrc).

# Services

## Dnsmasq

[Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) is a lightweight DNS and DHCP server with many [useful](https://www.cambus.net/nxdomain-hijacking-dnsmasq-to-the-rescue/) [features](https://www.g-loaded.eu/2010/09/18/caching-nameserver-using-dnsmasq/).

Install Dnsmasq:

```console
$ sudo apt -y install dnsmasq
```

Use my [configuration](https://github.com/drduh/config/blob/master/dnsmasq.conf) and blocklist(s):

```console
$ sudo cp ~/config/dnsmasq.conf /etc/dnsmasq.conf

$ cat ~/config/domains/* | sudo tee -a /etc/dnsmasq.conf
```

Or [customize your own](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).

Pick an upstream name server by uncommenting a line in /etc/dnsmasq.conf or use Google resolvers:

```console
$ echo "nameserver 169.254.169.254" | sudo tee /etc/resolv.dnsmasq
nameserver 169.254.169.254
```

**Optional** Install a DNS [blocklist](https://en.wikipedia.org/wiki/Hosts_(file)) ([alternative method](https://debian-administration.org/article/535/Blocking_ad_servers_with_dnsmasq)), for example:

```console
$ curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee /etc/dns-blocklist
```

Append any additional lists, such as `social-hosts`:

```console
$ curl https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/social-hosts | sudo tee --append /etc/dns-blocklist
```

Check the number of file entries and ensure no routable addresses were appended:

```console
$ wc -l /etc/dns-blocklist
66290 /etc/dns-blocklist

$ grep -ve "^127.0.0.1\|^0.0.0.0\|^#" /etc/dns-blocklist | sort | uniq
::1 ip6-localhost
::1 ip6-loopback
::1 localhost
255.255.255.255 broadcasthost
```

Restart the service:

```console
$ sudo service dnsmasq restart
```

Check the log to make sure it is running:

```console
$ sudo tail -F /tmp/dnsmasq
started, version 2.76 cachesize 2000
compile time options: IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect inotify
compile time options: IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect inotify
reading /etc/resolv.dnsmasq
using nameserver 169.254.169.254#53
read /etc/hosts - 6 addresses
read /etc/dns-blocklist - 63894 addresses
```

If it fails to start, try running it manually:

```console
$ sudo dnsmasq -C /etc/dnsmasq.conf -d
```

Query locally for an *A record* to confirm dnsmasq is working:

```console
$ dig +short a google.to @127.0.0.1
74.125.202.105
74.125.202.103
74.125.202.104
74.125.202.99
```

## DNSCrypt

[DNSCrypt](https://dnscrypt.info/) software can be used as a server and client to encrypt DNS traffic, as well as filter and shape queries.

> If you are running your own private or public recursive DNS server, adding support for the DNSCrypt protocol requires installing [DNSCrypt-Wrapper](https://github.com/Cofyc/dnscrypt-wrapper), the server-side DNSCrypt proxy.

To configure a private or public DNSCrypt server, first install [libsodium](https://github.com/jedisct1/libsodium) and [libevent](https://libevent.org/):

```console
$ sudo apt -y install libsodium-dev libevent-dev
```

Clone the DNSCrypt-Wrapper repository, make and install the software:

```console
$ git clone --recursive git://github.com/Cofyc/dnscrypt-wrapper.git

$ cd dnscrypt-wrapper

$ make configure

$ ./configure

$ sudo make install
```

See instructions [Cofyc/dnscrypt-wrapper](https://github.com/Cofyc/dnscrypt-wrapper) to configure or use [drduh/config/scripts/dnscrypt.sh](https://github.com/drduh/config/blob/master/scripts/dnscrypt.sh):

```console
$ mkdir ~/dnscrypt-keys

$ cd ~/dnscrypt-keys

$ cp ../config/scripts/dnscrypt.sh .

$ chmod +x dnscrypt.sh

$ sudo ./dnscrypt.sh
```

Copy the `sdns://` line to a client. To use a port other than 443, use https://dnscrypt.info/stamps to update the value.

Update firewall rules to allow the new port:

```console
$ gcloud compute firewall-rules create dnscrypt-udp-443 --network $NETWORK --allow udp:443 --source-ranges $(whois $(curl -s https://icanhazip.com) | grep CIDR | awk '{print $2}')
```

On a client, edit `dnscrypt-proxy.toml` to include the server stamp:

```
listen_addresses = ['127.0.0.1:40']
server_names = ['abc']
[static]
  [static.'abc']
  stamp = 'sdns://AQAAAAAAAAAAEj...ZA'
```

See [drduh/config/dnscrypt-proxy.toml](https://github.com/drduh/config/blob/master/dnscrypt-proxy.toml) and [jedisct1/dnscrypt-proxy/example-dnscrypt-proxy.toml](https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-proxy/example-dnscrypt-proxy.toml) for examples.

Start the client manually:

```console
$ sudo ./dnscrypt-proxy
```

Check the logfile:

```console
$ tail -f dnscrypt.log
[NOTICE] dnscrypt-proxy 2.0.23
[NOTICE] Loading the set of blocking rules from [blacklist.txt]
[NOTICE] Loading the set of forwarding rules from [forwarding-rules.txt]
[NOTICE] Loading the set of IP blocking rules from [ip-blacklist.txt]
[NOTICE] Now listening to 127.0.0.1:4200 [UDP]
[NOTICE] Now listening to 127.0.0.1:4200 [TCP]
[NOTICE] [abc] OK (DNSCrypt) - rtt: 10ms
[NOTICE] Server with the lowest initial latency: abc (rtt: 10ms)
[NOTICE] dnscrypt-proxy is ready - live servers: 1
```

Install it as service:

```console
$ sudo ./dnscrypt-proxy -service install

$ sudo ./dnscrypt-proxy -service start
```

Edit `/etc/dnsmasq.conf` and append `server=127.0.0.1#4200` to use dnscrypt with dnsmasq.

### Blacklist

DNSCrypt supports [query blocking](https://github.com/jedisct1/dnscrypt-proxy/wiki/Public-blacklists) with regular expression matching.

On the client, clone the dnscrypt-proxy repository and use the included Python script to generate a list, then configure dnscrypt to use it.

```console
$ git clone https://github.com/jedisct1/dnscrypt-proxy

$ cd dnscrypt-proxy/utils/generate-domains-blacklists

$ python3 generate-domains-blacklist.py > blacklist
Loading data from [file:domains-blacklist-local-additions.txt]
Loading data from [https://easylist-downloads.adblockplus.org/antiadblockfilters.txt]
[...]
Loading data from [https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt]
Loading data from [file:domains-time-restricted.txt]
Loading data from [file:domains-whitelist.txt]

$ mv blacklist ~/build/linux-x86_64/blacklist.txt

$ wc -l blacklist.txt
117838 blacklist.txt
```

## Privoxy

[Privoxy](https://www.privoxy.org/) is a non-caching web proxy with advanced filtering capabilities for enhancing privacy, modifying web page data and HTTP headers, controlling access, and removing ads and other obnoxious Internet junk.

Install Privoxy on the remote host:

```console
$ sudo apt -y install privoxy
```

Use my [configuration](https://github.com/drduh/config/blob/master/privoxy):

```console
$ sudo cp ~/config/privoxy/* /etc/privoxy
```

Or [customize your own](https://www.privoxy.org/faq/configuration.html).

Restart Privoxy:

```console
$ sudo service privoxy restart
```

Test Privoxy locally on the remote host:

```console
$ ALL_PROXY=127.0.0.1:8118 curl -I http://p.p/
HTTP/1.1 200 OK
Content-Length: 2500
Content-Type: text/html
Cache-Control: no-cache
Date: Sun, 01 May 2016 00:00:00 GMT
Last-Modified: Sun, 01 May 2016 00:00:00 GMT
Expires: Sat, 17 Jun 2000 12:00:00 GMT
Pragma: no-cache
```

Clients can use the remote proxy with [Secure Shell tunneling](https://en.wikipedia.org/wiki/Tunneling_protocol), also known as a ["poor man's VPN"](https://www.linuxjournal.com/content/ssh-tunneling-poor-techies-vpn) (**Note** `AllowTcpForwarding yes` must be enabled in `/etc/ssh/sshd_config` on the server to use these features, followed by `sudo service ssh restart`).

```console
$ ssh -NCL 5555:127.0.0.1:8118 duh
```

In another client terminal:

```console
$ ALL_PROXY='127.0.0.1:5555' curl https://icanhazip.com/
104.197.215.107
```

Requests will appear in Privoxy logs if logging is enabled:

```console
$ sudo tail -F /var/log/privoxy/logfile
```

Or to use ssh as a [SOCKS proxy](https://sanctum.geek.nz/arabesque/ssh-socks-and-curl/):

```console
$ ssh -NCD 7000 duh
```

In another client terminal:

```console
$ curl --proxy socks5h://127.0.0.1:7000 https://icanhazip.com/
104.197.215.107
```

## Tor

[Tor](https://www.torproject.org/) can be used as a public relay or as a [private bridge](https://www.torproject.org/docs/bridges.html.en) for you and your friends.

[Install Tor](https://www.torproject.org/docs/tor-relay-debian.html.en) on the server - by default Tor does **not** relay nor exit traffic; it only provides a local port for outbound connections.

```console
$ sudo apt -y install tor
```

**Optional** Install and configure [anonymizing relay monitor (arm)](https://www.atagar.com/arm/), a terminal-based status monitor for Tor.

```console
$ sudo apt -y install tor-arm

$ sudo arm
```

Use my [configuration](https://github.com/drduh/config/blob/master/torrc):

```console
$ sudo cp ~/config/torrc /etc/tor/torrc
```

### DNS over Tor

Tor can listen locally to resolve DNS A, AAAA and PTR records anonymously. To use, add a local address to `/etc/tor/torrc`:
    
```
DNSPort 127.26.255.1:53
```

Then append `server=127.26.255.1` to `/etc/dnsmasq.conf` and restart both services.

### Obfuscation

Additionally, obfuscate Tor traffic by using [obfsproxy](https://www.torproject.org/projects/obfsproxy.html.en) or some other [Tor pluggable transport](https://www.torproject.org/docs/pluggable-transports.html.en).

To install the latest version of obfs4proxy, first install [Golang](https://golang.org/):

```console
$ sudo apt -y install golang
```

Create a temporary directory, [download and build](https://golang.org/cmd/go/) [obfs4proxy](https://gitweb.torproject.org/pluggable-transports/obfs4.git):

```console
$ export GOPATH=$(mktemp -d)

$ go get git.torproject.org/pluggable-transports/obfs4.git/obfs4proxy
```

**Note** If this fails for any reason, you likely need a more recent version of [Go](https://debian-administration.org/article/727/Installing_the_Go_programming_language_on_Debian_GNU/Linux):

```console
$ go get git.torproject.org/pluggable-transports/obfs4.git/obfs4proxy
# github.com/refraction-networking/utls
/tmp/tmp.s8JQjim8W7/src/github.com/refraction-networking/utls/tls.go:106: undefined: time.Until
# golang.org/x/net/http2
/tmp/tmp.s8JQjim8W7/src/golang.org/x/net/http2/server.go:214: h1.IdleTimeout undefined (type *http.Server has no field or method
 IdleTimeout)
/tmp/tmp.s8JQjim8W7/src/golang.org/x/net/http2/server.go:215: h1.IdleTimeout undefined (type *http.Server has no field or method
[...]

$ go version
go version go1.7.4 linux/amd64

$ curl -O https://dl.google.com/go/go1.12.5.linux-amd64.tar.gz

$ sudo tar -C /usr/local -xzf go1.12.5.linux-amd64.tar.gz

$ /usr/local/go/bin/go version
go version go1.12.5 linux/amd64

$ /usr/local/go/bin/go get git.torproject.org/pluggable-transports/obfs4.git/obfs4proxy
```

Confirm it's built and install it:

```console
$ echo $?
0

$ $GOPATH/bin/obfs4proxy -version
obfs4proxy-0.0.11-dev

$ sudo service tor stop

$ sudo cp $GOPATH/bin/obfs4proxy /usr/local/bin
```

Set the program file owner to `root`:

```console
$ sudo chown root:root /usr/local/bin/obfs4proxy
```

Edit `/etc/tor/torrc` to include:

```
ORPort 9993
ExtORPort auto
BridgeRelay 1
ServerTransportPlugin obfs4 exec /usr/local/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:10022
```

Restart Tor:

```console
$ sudo service tor restart
```

Verify `obfs4proxy` is accepting connections:

```console
$ sudo lsof -Pni | grep obfs
obfs4prox 6507 debian-tor    3u  IPv6  62584      0t0  TCP *:10022 (LISTEN)
```

Verify connections on the server itself over Tor are working:

```console
$ curl --socks5 127.0.0.1:9050 https://icanhazip.com/
[a Tor exit node IP address]
```

Update firewall rules to allow the new proxy listening port (in this case, TCP port 10022) for your current IP address range:

```console
$ gcloud compute firewall-rules create obfs4-tcp-10022 \
    --network $NETWORK --allow tcp:10022 \
    --source-ranges $(whois $(curl -s https://icanhazip.com) | grep CIDR | awk '{print $2}')
```

If Tor did not start, try starting it manually (`sudo` may be required to bind to [privileged ports](https://www.w3.org/Daemon/User/Installation/PrivilegedPorts.html)):

```console
$ tor -f /etc/tor/torrc
```

Copy the bridgeline, filling in the IP address and port:

```console
$ sudo tail -n1 /var/lib/tor/pt_state/obfs4_bridgeline.txt
Bridge obfs4 <IP ADDRESS>:<PORT> <FINGERPRINT> cert=4ar[...]8FA iat-mode=0

$ sudo tail -n1 /var/lib/tor/pt_state/obfs4_bridgeline.txt | awk '{print $1,$2,"104.197.215.107:10022",$(NF-1),$(NF)}'
Bridge obfs4 104.197.215.107:10022 cert=4ar[...]8FA iat-mode=0
```

To connect from a client, edit `torrc` to use the IP address and assigned port, for example:

```
UseBridges 1
Bridge obfs4 104.197.215.107:10022 cert=4ar[...]8FA iat-mode=0
```

Using [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en), select Configure and Enter custom bridges:

<img width="500" src="https://cloud.githubusercontent.com/assets/12475110/15528945/844fe950-2238-11e6-8348-3084cf6341d9.png">

### Onion Service

**Optional** To host an [Onion Service](https://www.torproject.org/docs/onion-services), append something like this to `/etc/tor/torrc` on the server (for example, to use with a Web server):

```
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:80
```

Restart Tor:

```console
$ sudo service tor restart
```

Get the service hostname:

```console
$ sudo cat /var/lib/tor/hidden_service/hostname
pqccxgxxxxxxxl5h.onion
```

You can also host services like [ssh](https://tor.stackexchange.com/questions/123/how-can-i-anonymize-my-ssh-traffic-using-the-tor-network) as a onion service.

To generate a specific .onion hostname, [some](https://security.stackexchange.com/questions/29772/how-do-you-get-a-specific-onion-address-for-your-hidden-service) [software](https://github.com/ReclaimYourPrivacy/eschalot) exists.

## Certificates

Set up a [public-key infrastructure](https://security.stackexchange.com/questions/87564/how-does-ssl-tls-pki-work) to use your own keys and certificates for VPN, an HTTPS-enabled Web server, etc.

To create a certificate authority, server and client certificates, download the following [script](https://github.com/drduh/config/blob/master/scripts/pki.sh).

It is recommended running the script to generate keys client-side, in a trusted computing environment, preferably [air-gapped](https://en.wikipedia.org/wiki/Air_gap_(networking)).

```console
$ mkdir ~/pki && cd ~/pki

$ cp ~/config/scripts/pki.sh pki/
```

Read through and edit the script and variables, especially `CN_` ones, to your suit your needs:

```console
$ vim pki.sh
```

Make the script executable:

```console
$ chmod +x pki.sh
```

Change OpenSSL certificate requirements to disable mandatory location fields:

```console
$ sudo sed -i.bak "s/= match/= optional/g" /usr/lib/ssl/openssl.cnf
```

Run the script, accepting prompts with `y` to sign certificates and commit changes:

```console
$ ./pki.sh
Generating RSA private key, 4096 bit long modulus
........................................................................++
.....................................++
[...]
Sign the certificate? [y/n]:y
```

If there were no errors, the script created private and public keys for a certificate authority, a server and a client - along with certificate request (srl) and configuration files (cnf).

To check a certificate file (`.pem` extension) with OpenSSL:

```console
$ openssl x509 -in ca.pem -noout -subject -issuer -enddate
subject= /CN=4CC90cC34b
issuer= /CN=4CC90cC34b
notAfter=Dec 1 00:00:00 2020 GMT
```

You could also use [OpenVPN/easy-rsa](https://github.com/OpenVPN/easy-rsa) or [Let's Encrypt](https://letsencrypt.org).

## OpenVPN

[OpenVPN](https://openvpn.net/index.php/open-source/downloads.html) is free, open source TLS-based VPN server and client software.

Starting with the client, install OpenVPN:

```console
$ sudo apt -y install openvpn
```

Use my [configuration](https://github.com/drduh/config/blob/master/openvpn/server.ovpn):

```console
$ sudo cp ~/config/openvpn/server.ovpn /etc/openvpn
```

Or [customize your own](https://openvpn.net/index.php/open-source/documentation/howto.html#server).

Preferably client-side (where there is more entropy available), generate a [static key](https://openvpn.net/index.php/open-source/documentation/miscellaneous/78-static-key-mini-howto.html) so that only trusted clients can attempt connections (extra authentication on top of TLS):

```console
$ openvpn --genkey --secret ta.key
```

Also client-side, create [Diffie-Hellman key exchange parameters](https://security.stackexchange.com/questions/38206/can-someone-explain-a-little-better-what-exactly-is-accomplished-by-generation-o):

```console
$ openssl dhparam -dsaparam -out dh.pem 4096
```

Copy the following files from the previous section to the server. Note that the only *private* key sent remotely is for the server itself (`server.key`):

```console
$ scp ta.key dh.pem ca.pem server.pem server.key duh:~
```

On the server, move the files into place:

```console
$ sudo mkdir /etc/pki

$ sudo mv ca.pem server.pem server.key dh.pem ta.key /etc/pki/

$ sudo chmod 0400 /etc/pki/server.key /etc/pki/ta.key /etc/pki/dh.pem
```

Enable [IP forwarding](https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux) and make the change permanent:

```console
$ sudo sysctl -w net.ipv4.ip_forward=1

$ echo "net.ipv4.ip_forward = 1" | sudo tee --append /etc/sysctl.conf
```

Create a [NAT](https://serverfault.com/questions/267286/openvpn-server-will-not-redirect-traffic/427756#427756) for VPN clients:

```console
$ sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.8.0.0/16 -j MASQUERADE
```

**Optional** Route all HTTP (TCP port 80) traffic through Privoxy.

```console
$ sudo iptables -t nat -A PREROUTING --source 10.8.0.0/16 -p tcp -m tcp --dport 80 -j DNAT --to 10.8.0.1:8118
```
    
Make the firewall rules permanent:

```console
$ sudo apt -y install iptables-persistent

$ sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

Append `10.8.0.1` as a Dnsmasq listening address and restart the services:

```console
$ sudo sed -i.bak "s/listen-address=127.0.0.1/listen-address=127.0.0.1,10.8.0.1/g" /etc/dnsmasq.conf

$ sudo service dnsmasq restart

$ sudo service openvpn restart
```

Check the OpenVPN log:

```console
$ sudo tail -F /var/log/openvpn.log
TUN/TAP device tun0 opened
TUN/TAP TX queue length set to 100
do_ifconfig, tt->ipv6=0, tt->did_ifconfig_ipv6_setup=0
/sbin/ip link set dev tun0 up mtu 1500
/sbin/ip addr add dev tun0 10.8.0.1/24 broadcast 10.8.0.255
UDPv4 link local (bound): [undef]
UDPv4 link remote: [undef]
IFCONFIG POOL: base=10.8.0.2 size=252, ipv6=0
Initialization Sequence Completed
```

If OpenVPN still fails due to unknown ciphers, you may need to install a newer OpenVPN server version - see [OpenvpnSoftwareRepos](https://community.openvpn.net/openvpn/wiki/OpenvpnSoftwareRepos).

Update the remote hosts firewall rules to allow the new VPN listening port (in this case, UDP port 443).

For each connecting device, edit a [client configuration](https://openvpn.net/index.php/open-source/documentation/howto.html#client) using [my configuration](https://github.com/drduh/config/blob/master/openvpn/client.ovpn):

```console
$ mkdir ~/vpn

$ cd ~/vpn

$ cp ~/config/openvpn/client.ovpn .
```

Add the CA certificate, client certificate and client key material to the configuration:

```console
$ (echo "<ca>" ; cat ~/pki/ca.pem ; echo "</ca>\n<cert>" ; cat ~/pki/client.pem; echo "</cert>\n<key>" ; cat ~/pki/client.key ; echo "</key>") >> client.ovpn
```

Install and start OpenVPN:

```console
$ sudo apt -y install openvpn

$ cd ~/vpn

$ sudo openvpn --config client.ovpn
[...]
TLS: Initial packet from [AF_INET]104.197.215.107:443, sid=6901c819 3e11276e
VERIFY OK: depth=2, CN=Duh Authority
Validating certificate key usage
++ Certificate has key usage  00a0, expects 00a0
VERIFY KU OK
Validating certificate extended key usage
++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
VERIFY EKU OK
VERIFY OK: depth=0, CN=duh.to
[...]
```

Verify the local IP address is the same as the remote host:

```console
$ curl -4 https://icanhazip.com/
104.197.215.107
```
    
**Note** If IPv6 is disabled, the connection may fail - you'll need to disable these options on the server to connect:

```
#server-ipv6 2001:db8:123::/64
#push "route-ipv6 2000::/3"
```

To connect from Android, install [OpenVPN Connect](https://play.google.com/store/apps/details?id=net.openvpn.openvpn).

Copy `client.ovpn` and `ta.key` to a directory on the Android device using adb or Android File Transfer.

Select **Import** > **Import Profile from SD card** and select `client.ovpn`, perhaps in the Download folder.

If the profile was was successfully imported, select **Connect**.

Start OpenVPN:

```console
$ sudo ~/homebrew/sbin/openvpn --config client.ovpn
OpenVPN 2.4.4 x86_64-apple-darwin16.7.0 [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [MH/RECVDA] [AEAD] built on Oct  2 2017
[...]
TLS: Initial packet from [AF_INET]104.197.215.107:443, sid=db4ecf82 4e4e4c5b
VERIFY OK: depth=2, CN=Duh Authority
Validating certificate key usage
++ Certificate has key usage  00a0, expects 00a0
VERIFY KU OK
Validating certificate extended key usage
++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
VERIFY EKU OK
VERIFY OK: depth=0, CN=duh.to
[...]
Initialization Sequence Completed
```

Verify traffic is routed through the remote host:

```console
$ curl -4 https://icanhazip.com/
104.197.215.107
```

## Web Server

**Optional** You may want to run a Web server to serve static or dynamic pages.

Install [Lighttpd](https://www.lighttpd.net/) with [ModMagnet](https://redmine.lighttpd.net/projects/1/wiki/Docs_ModMagnet):

```console
$ sudo apt -y install lighttpd lighttpd-mod-magnet
```

Use my [configuration](https://github.com/drduh/config/blob/master/lighttpd/lighttpd.conf):

```console
$ sudo cp ~/config/lighttpd/lighttpd.conf /etc/lighttpd

$ sudo cp ~/config/lighttpd/magnet.luau /etc/lighttpd
```

Or [customize your own](https://redmine.lighttpd.net/projects/1/wiki/TutorialConfiguration).

**Note** Lighttpd expects the server private key and certificate to be stored in one file as the `ssl.pemfile` argument:

```console
$ sudo cat /etc/pki/server.key /etc/pki/server.pem | sudo tee /etc/pki/lighttpd.pem
```

You may need to comment out the following line in `/etc/lighttpd/lighttpd.conf` in order to accept requests on Internet-facing interfaces:

```
#server.bind = "127.0.0.1"
```

Restart Lighttpd:

```console
$ sudo service lighttpd restart
```

Check that it's running - look for the process listening on TCP ports 80 or 443:

```console
$ sudo lsof -Pni | grep lighttpd
lighttpd  3291   www-data    4u  IPv4  18206      0t0  TCP *:80 (LISTEN)
lighttpd  3291   www-data    5u  IPv4  18207      0t0  TCP *:443 (LISTEN)
```

If it failed to start, try running it directly to check for errors:

```console
$ sudo lighttpd -f /etc/lighttpd/lighttpd.conf -D
```

Update firewall rules to allow the new HTTP/HTTPS listening port(s) (in this example, TCP port 80 and 443).

Create some content:

```console
$ echo "Hello, World" | sudo tee /var/www/index.html
```

Once Lighttpd is running, request a page from the server in a Web browser or by using cURL:

```console
$ curl -vv http://duh.to/
Hello, World
```

You can use [client certificates](https://security.stackexchange.com/questions/14589/advantages-of-client-certificates-for-client-authentication) as a means of authentication and authorization, rather than relying on user-provided passwords. See my Lighttpd [configuration](https://github.com/drduh/config/blob/master/lighttpd.conf) for an example.

## XMPP

Run your own [XMPP](https://en.wikipedia.org/wiki/XMPP) chat server with [Prosody](https://prosody.im/). Client can use [Off The Record (OTR) messaging](https://otr.cypherpunks.ca/), a form of secure messaging which includes encryption, authentication, deniability and perfect forward secrecy, to communicate privately.

Install Prosody:

```console
$ sudo apt -y install prosody
```

Use my [configuration](https://github.com/drduh/config/blob/master/prosody.cfg.lua) and edit it to suit your needs:

```console
$ sudo cp ~/config/prosody.cfg.lua /etc/prosody
```

Or [customize your own](https://prosody.im/doc/example_config). See also [Advanced ssl config](https://prosody.im/doc/advanced_ssl_config).

Use Diffie-Hellman key exchange parameters from the [Certificate](#certificates) steps:

```console
$ sudo cp ~/pki/dh.pem /etc/pki/dh.pem
```

Copy the server certificate and key from the [Certificate](#certificates) steps:

```console
$ sudo cp ~/pki/server.pem /etc/pki/xmpp-cert.pem

$ sudo cp ~/pki/server.key /etc/pki/xmpp-key.pem
```

Append the CA to the server certificate:

```console
$ cd ~/pki && cat server.pem ca.pem | sudo tee /etc/pki/xmpp-cert.pem
```

Or generate a new self-signed certificate:

```console
$ sudo openssl req -x509 -newkey rsa:4096 -days 365 -sha512 -subj "/CN=server.name" \
  -nodes -keyout /etc/pki/xmpp-key.pem -out /etc/pki/xmpp-cert.pem
```

Set file ownership:

```console
$ sudo chown prosody:prosody /etc/pki/xmpp-*.pem
```

Restart Prosody:

```console
$ sudo service prosody restart
```

Ensure it's running and listening:

```console
$ sudo tail -n1 /var/log/prosody/prosody.log
mod_posix       info    Successfully daemonized to PID 1831

$ sudo lsof -Pni | grep prosody
lua5.1     1831    prosody    6u  IPv6 317986      0t0  TCP *:5269 (LISTEN)
lua5.1     1831    prosody    7u  IPv4 317987      0t0  TCP *:5269 (LISTEN)
lua5.1     1831    prosody    8u  IPv6 317990      0t0  TCP *:5222 (LISTEN)
lua5.1     1831    prosody    9u  IPv4 317991      0t0  TCP *:5222 (LISTEN)
```

Update firewall rules to allow the new prosody listening ports (in this example, TCP ports 5222 and 5269):

```console
$ gcloud compute firewall-rules create xmpp-tcp-5222-5269 --network $NETWORK --allow tcp:5222,tcp:5269 --source-ranges $(curl -s https://icanhazip.com)
```

Create a new user:

```console
$ sudo prosodyctl adduser doc@duh.to
```

**Important** The domain name must match the server certificate common name (*CN_SERVER* in *pki.sh*) - check with `sudo openssl x509 -in /etc/pki/xmpp-cert.pem -noout -subject`

### Federating

For others to communicate with your XMPP server, you must [configure DNS records](https://xmpp.org/rfcs/rfc6120.html#tcp-resolution-prefer) for [interdomain federation](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/im_presence/interdomain_federation):

`_xmpp-client._tcp` of type `SRV` with data `0 5 5222 duh.to.`

`_xmpp-server._tcp` of type `SRV` with data `0 5 5269 duh.to.`

After a little while, check domain SRV records:

```console
$ dig +short srv _xmpp-server._tcp.duh.to
0 5 5269 duh.to.

$ dig +short srv _xmpp-client._tcp.duh.to
0 5 5222 duh.to.
```

### Using

To connect from a client, use [Profanity](http://profanity.im/)

```console
$ sudo apt -y install profanity

$ profanity
```

Log in by typing `/connect doc@duh.to` and entering the password when prompted.

Generate OTR keys by typing `/otr gen` - this part may take a while.

Send a message to a contact by typing `/msg user@duh.to` - to navigate tabs, use `/win 1`, `/win 2`, etc.

To start OTR, type `/otr start` - Profanity will show *OTR session started (untrusted)*.

To authenticate the chat partner, type `/otr question foo? bar` where `bar` is an answer to `foo?` which only the person you assume to be speaking with can answer. If the person answers correctly, Profanity will show *Authentication successful* followed by *OTR session trusted* - now you can be sure the connection is encrypted and authenticated.

Or use [agl/xmpp-client](https://github.com/agl/xmpp-client):

```console
$ go get github.com/agl/xmpp-client

$ $GOPATH/bin/xmpp-client
```

If you can't connect, check for errors in `/var/log/prosody/prosody.err` on the server.

To verify the SHA256 fingerprint matches the certificate on the server:

```console
$ openssl x509 -in /etc/pki/xmpp-cert.pem -fingerprint -noout -sha256
```

To view and verify the XMPP server's certificate fingerprint remotely, use the `openssl` command from a client:

```console
$ echo -e | openssl s_client -connect duh.to:5222 -starttls xmpp | openssl x509 -noout -fingerprint -sha256 | tr -d ':'
[...]
SHA256 Fingerprint=9B759D41E3DE30F9D2F902027D792B65D950A98BBB6D6D56BE7F2528453BF8E9
```

**Note** If using agl/xmpp-client and custom certificates (i.e., not signed by a trusted root CA), you will need to [manually add](https://github.com/agl/xmpp-client/issues/44#issuecomment-39539794) the server's SHA256 fingerprint to `~/.xmpp-client`, like:

```
"ServerCertificateSHA256": "9B759D41E3DE30F9D2F902027D792B65D950A98BBB6D6D56BE7F2528453BF8E9"
```

If an error occurs while attempting to connect, check `/var/log/prosody/prosody.err` on the server.

# Finish

Reboot the instance and make sure everything still works. If not, you'll need to automate certain programs to start up on their own (for example, Privoxy will fail to start if OpenVPN does not first create a tunnel interface to bind to).

With this guide, a secure server with several privacy and security enchancing services can be setup in less than an hour. The server can be used to circumvent firewalls, provide strong encryption and overall improve online experience, all for a low monthly cost (average ~$35 per month for a "standard" instance.) To save money, consider using [Preemptible VM instances](https://cloud.google.com/compute/docs/instances/preemptible) which can be started right back up with a script.

