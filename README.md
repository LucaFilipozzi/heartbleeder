# heartbleeder

Tests your servers for OpenSSL [Heartbleed](http://heartbleed.com/)
vulnerability ([CVE-2014-0160](https://www.openssl.org/news/secadv_20140407.txt)).

Understands CIDR syntax, allowing specification of entire subnets.

## usage

Prepare an input file containing mode:host:port entries and/or mode:cidr:port
entries (IPv4 only), where mode is one of 'standard' or 'starttls' (coming soon).

```text
$ cat /path/to/input.txt
standard:www.example.com:443
standard:192.168.1.1:443
standard:192.168.1.1/32:443
standard:192.168.1.16/28:443
standard:192.168.2.0/24:443
standard:192.168.2.0/24:8443
```

Run the script against the input file:

```text
$ cd ~/go/src/github.com/LucaFilipozzi/heartbleeder
$ cat /path/to/input.txt | go heartbleader.go
Y,www.example.com:443,heartbeat enabled and vulnerable!
Y,192.168.1.1:443,heartbeat enabled and vulnerable!
Y,192.168.1.1:443,heartbeat enabled and vulnerable!
N,192.168.1.16:443,host unreachable
N,192.168.1.17:443,host unreachable
N,192.168.1.18:443,host unreachable
E,192.168.1.19:443,error injecting payload
...
N,192.168.1.32:443,host unreachable
N,192.168.2.0:443,heartbeat enabled but not vulnerable
...
N,192.168.2.255:443,heartbeat enabled but not vulnerable
N,192.168.2.0:8443,heartbeat enabled but not vulnerable
...
N,192.168.2.255:8443,host unreachable
```

Or build an executable:

```text
$ cd ~/go/src/github.com/LucaFilipozzi/heartbleeder
$ go install
```

And run it against the input file:

```text
$ cat /path/to/input.txt | ~/go/bin/heartbleeder
Y,www.example.com:443,heartbeat enabled and vulnerable!
...
N,192.168.2.255:8443,host unreachable
```

The format of the output is CSV format with three columns:

1. the result code (Y indicates vulnerable, N indicates not vulnerable or not reachable and E indicates an error occurred)
2. the target (IPv4 address / hostname and the port scanned)
3. the reason for the given result code

## installation

Requires [Go](http://golang.org/) version >= 1.2.

Requires https://github.com/mikioh/ipaddr.

On a typical Linux box with Go installed in /usr/local/go, the following:

```text
$ export GOROOT=/usr/local/go
$ export GOPATH=$HOME/go
$ export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
$ mkdir -p $GOPATH/{bin,pkg,src}
$ cd $GOPATH
$ go get github.com/mikioh/ipaddr
$ go get github.com/LucaFilipozzi/heartbleeder
```

should result in a 'heartbleeder' executable in $GOPATH/bin

## improvements

* support scanning of StartTLS-enabled protocols

## credits

The TLS implementation was borrowed from the Go standard library.

Forked from Jonathan Rudenberg's original work, augmented with Richard Tilley's
parallelization enhancements.

