package main

import (
    "bufio"
    "encoding/csv"
    "flag"
    "fmt"
    "net"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/mikioh/ipaddr"
    "github.com/LucaFilipozzi/heartbleeder/tls"
)

type Command struct {
    mode string
    host string
    port string
    timeout time.Duration
}

type Response struct {
    result string
    reason string
}

func test_for_heartbleed(command Command) Response {
    var netConn net.Conn
    var tlsConn *tls.Conn
    var err error
    var line string
    var greetingPattern string
    var responsePattern string
    var starttlsRequest string

    // establish a tcp connection
    netConn, err = net.DialTimeout("tcp", command.host + ":" + command.port, command.timeout)
    if err != nil {
        return Response{"N", "tcp connection failed"}
    }
    err = netConn.SetDeadline(time.Now().Add(2 * command.timeout))
    if err != nil {
        return Response{"N", "tcp connection failed"}
    }

    if command.mode != "https" {
        switch command.mode {
            case "ftp":
                greetingPattern = "^220 "
                starttlsRequest = "AUTH TLS"
                responsePattern = "^234 "
            case "imap":
                greetingPattern = "^\\* "
                starttlsRequest = "a001 STARTTLS"
                responsePattern = "^a001 OK "
            case "pop3":
                greetingPattern = "^\\+OK "
                starttlsRequest = "STLS"
                responsePattern = "^\\+OK "
            case "smtp":
                greetingPattern = "^220 "
                starttlsRequest = "STARTTLS\r\n"
                responsePattern = "^220 "
        }

        netConnReader := bufio.NewReader(netConn)
        netConnWriter := bufio.NewWriter(netConn)

        // loop until greeting seen or timeout
        greetingRegexp := regexp.MustCompile(greetingPattern)
        for {
            line, err = netConnReader.ReadString('\n')
            if err != nil {
                return Response{"N", "starttls greeting failed"}
            }
            if greetingRegexp.MatchString(strings.TrimRight(line, "\r")) {
                break
            }
        }

        // send starttls request
        _, err = netConnWriter.WriteString(starttlsRequest)
        if err != nil {
            return Response{"N", "starttls request failed"}
        }
        err = netConnWriter.Flush()
        if err != nil {
            return Response{"N", "starttls request failed"}
        }

        // recv starttls response
        line, err = netConnReader.ReadString('\n')
        if err != nil {
            return Response{"N", "starttls response failed"}
        }
        responseRegexp := regexp.MustCompile(responsePattern)
        if !responseRegexp.MatchString(strings.TrimRight(line, "\r")) {
            return Response{"N", "starttls response failed"}
        }
    }

    // initiate tls handshake
    tlsConn = tls.Client(netConn, &tls.Config{InsecureSkipVerify: true, ServerName: command.host})
    err = tlsConn.Handshake()
    if err != nil {
        return Response{"N", "tls handshake failed"}
    }

    // send heartbeat payload
    err = tlsConn.WriteHeartbeat(1, nil)
    if err == tls.ErrNoHeartbeat {
        return Response{"N", "heartbeat disabled"}
    }
    if err != nil {
        return Response{"N", "error injecting payload"}
    }

    // recv heartbeat response
    readErr := make(chan error)
    go func() {
        _, _, err := tlsConn.ReadHeartbeat()
        readErr <- err
    }()

    select {
        case err := <-readErr:
            if err == nil {
                return Response{"Y", "heartbeat vulnerable!"}
            } else {
                return Response{"N", "heartbeat not vulnerable"}
            }
        case <-time.After(command.timeout):
            return Response{"N", "heartbeat timed out"}
    }
}

func worker(channel chan Command, waitgrp *sync.WaitGroup, writer *csv.Writer) {
    record := make([]string,5)
    for command := range channel {
        response := test_for_heartbleed(command)
        record[0] = response.result
        record[1] = command.mode
        record[2] = command.host
        record[3] = command.port
        record[4] = response.reason
        writer.Write(record)
        waitgrp.Done()
    }
}

func main() {
    verboseFlag := flag.Bool("verbose", false, "enable verbosity on stderr")
    timeoutFlag := flag.Duration("timeout", 1*time.Second, "Timeout after sending heartbeat")
    workersFlag := flag.Int("workers", 512, "number of workers with which to scan targets")
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Options:\n")
        flag.PrintDefaults()
    }
    flag.Parse()

    // set up a csv writer that outputs to stdout
    writer := csv.NewWriter(os.Stdout)

    // set up the channel for worker communication
    channel := make(chan Command, 2 * *workersFlag)

    // set up a wait group to track the workers
    waitgrp := &sync.WaitGroup{}

    // spin up the workers
    for i := 0; i < *workersFlag; i++ {
        go worker(channel, waitgrp, writer)
    }

    // process each line from standard input
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Count(line, ",") != 2 {
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "skipping", line, "does not parse correctly")
            }
            continue
        }

        parts := strings.Split(line, ",")
        mode := parts[0]
        spec := parts[1]
        port := parts[2]

        switch mode {
            case "ftp", "https", "imap", "ldap", "pop3", "smtp":
                // do nothing - these are the valid modes
            default:
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "skipping", line, "invalid mode")
                }
                continue
        }

        if strings.Contains(spec, "/") {
            ip, ipnet, err := net.ParseCIDR(spec)
            if err != nil {
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "skipping", line, err)
                }
                continue
            }

            nbits, _ := ipnet.Mask.Size()
            prefix, err := ipaddr.NewPrefix(ipnet.IP, nbits)
            if err != nil {
                if *verboseFlag {
                    fmt.Fprintln(os.Stdout, "skipping", line, err)
                }
            }

            for host := range prefix.HostIter(ip) {
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "scanning", mode, host.String(), port)
                }
                waitgrp.Add(1)
                channel <- Command{mode, host.String(), port, *timeoutFlag}
            }
        } else {
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "scanning", mode, spec, port)
            }
            waitgrp.Add(1)
            channel <- Command{mode, spec, port, *timeoutFlag}
        }
    }

    // wait for all workers to finish and clean up
    waitgrp.Wait()
    close(channel)
    writer.Flush()
}
