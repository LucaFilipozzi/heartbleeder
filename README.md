# heartbleeder

Tests your servers for OpenSSL [Heartbleed](http://heartbleed.com/)
vulnerability ([CVE-2014-0160](https://www.openssl.org/news/secadv_20140407.txt)).

Understands CIDR syntax, allowing specification of entire subnets.

## usage

Prepare an input file containing hostname entries or CIDR entries (IPv4 only).
If no port is specified, 443 is assumed.  Specify a single port by appending
with colon.  Does not (yet) support STARTTLS-based protocols.

```text
$ cat /path/to/input.txt
www.example.com
192.168.1.1
192.168.1.16/28
192.168.2.0/24:443
192.168.2.0/24:8443
```

Run the script against the input file:

```text
$ cd ~/go/src/github.com/LucaFilipozzi/heartbleeder
$ cat /path/to/input.txt | go heartbleader.go
N www.example.com:443
Y 192.168.1.1:443
N 192.168.1.16:443
N 192.168.1.17:443
N 192.168.1.18:443
E 192.168.1.19:443
...
N 192.168.1.32:443
N 192.168.2.0:443
...
N 192.168.2.255:443
N 192.168.2.0:8443
...
N 192.168.2.255:8443
```

Or build an executable:

```text
$ cd ~/go/src/github.com/LucaFilipozzi/heartbleeder
$ go install
```

And run it against the input file:

```text
$ cat /path/to/input.txt | ~/go/bin/heartbleeder
N www.example.com:443
...
N 192.168.2.255:8443
```

The format of the output is in two columns:

1. result code where Y indicates vulnerable, N indicates not vulnerable or not reachable and E indicates an error occurred
2. the IPv4 address or hostname and the port scanned

## installation

Requires [Go](http://golang.org/) version >= 1.2.

Requires https://github.com/ziutek/utils.

On a typical Linux box with Go installed in /usr/local/go, the following:

```text
$ export GOROOT=/usr/local/go
$ export GOPATH=$HOME/go
$ export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
$ mkdir -p $GOPATH/{bin,pkg,src}
$ cd $GOPATH
$ go get github.com/ziutek/utils
$ go get github.com/LucaFilipozzi/heartbleeder
```

should result in a 'heartbleeder' executable in $GOPATH/bin

## improvements

* incorporate improvements from Jonathan Rudenbert's trunk
* prevent scanning the network and broadcast addresses of a CIDR
* support scanning of StartTLS-enabled protocols

## credits

The TLS implementation was borrowed from the Go standard library.

Forked from Jonathan Rudenberg's original work, augmented with Richard Tilley's
parallelization enhancements.

