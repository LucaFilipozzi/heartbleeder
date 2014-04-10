# heartbleeder

Tests your servers for OpenSSL [Heartbleed](http://heartbleed.com/)
vulnerability ([CVE-2014-0160](https://www.openssl.org/news/secadv_20140407.txt)).

Understands CIDR syntax, allowing specification of entire subnets.

## usage

Prepare an input file containing CIDR entries (IPv4 only):

```text
$ cat /path/to/input.txt
192.168.1.1
192.168.1.16/28
```

Run the script against the input file:

```text
$ cd go/src/github.com/LucaFilipozzi/heartbleeder
$ cat /path/to/input.txt | go heartbleader.go
Y 192.168.1.1:443
N 192.168.1.16:443
N 192.168.1.17:443
N 192.168.1.18:443
E 192.168.1.19:443
.
.
.
N 192.168.1.32:443
```

```text
$ cat /path/to/input.txt | go run heartbleeder.go
```

Requires Go version >= 1.2.

## credits

The TLS implementation was borrowed from the Go standard library.

Forked from Jonathan Rudenberg implementation with Richard Tilley
parallelization enhancements.
