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
}

type Response struct {
    mode string
    host string
    port string
    result string
    reason string
}

func ProcessCommand(command Command, timeout time.Duration) (response Response) {
    response.mode = command.mode
    response.host = command.host
    response.port = command.port
    response.result = "N"

    var netConn net.Conn
    var tlsConn *tls.Conn
    var err error
    var line string
    var greetingPattern string
    var responsePattern string
    var starttlsRequest string

    // establish a tcp connection
    netConn, err = net.DialTimeout("tcp", command.host + ":" + command.port, timeout)
    if err != nil {
        response.reason = "tcp connection failed"
        return
    }
    err = netConn.SetDeadline(time.Now().Add(2 * timeout))
    if err != nil {
        response.reason = "tcp connection failed"
        return
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
                response.reason = "starttls greeting failed"
                return
            }
            if greetingRegexp.MatchString(strings.TrimRight(line, "\r")) {
                break
            }
        }

        // send starttls request
        _, err = netConnWriter.WriteString(starttlsRequest)
        if err != nil {
            response.reason = "starttls request failed"
            return
        }
        err = netConnWriter.Flush()
        if err != nil {
            response.reason = "starttls request failed"
            return
        }

        // recv starttls response
        line, err = netConnReader.ReadString('\n')
        if err != nil {
            response.reason = "starttls response failed"
            return
        }
        responseRegexp := regexp.MustCompile(responsePattern)
        if !responseRegexp.MatchString(strings.TrimRight(line, "\r")) {
            response.reason = "starttls response failed"
            return
        }
    }

    // initiate tls handshake
    tlsConn = tls.Client(netConn, &tls.Config{InsecureSkipVerify: true, ServerName: command.host})
    err = tlsConn.Handshake()
    if err != nil {
        response.reason = "tls handshake failed"
        return
    }

    // send heartbeat payload
    err = tlsConn.WriteHeartbeat(1, nil)
    if err == tls.ErrNoHeartbeat {
        response.reason = "heartbeat disabled"
        return
    }
    if err != nil {
        response.reason = "E"
        response.reason = "error injnecting payload"
        return
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
                response.result = "Y"
                response.reason = "heartbeat vulnerable!"
                return
            } else {
                response.reason = "heartbeat not vulnerable"
                return
            }
        case <-time.After(timeout):
            response.reason = "heartbeat timed out"
            return
    }
}

func main() {
    // parse command line arguments
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

    // set up the channels for worker communication
    commandChannel := make(chan Command, 4096)
    responseChannel := make(chan Response, 4096)

    // set up a wait group to track the workers
    waitgrp := &sync.WaitGroup{}

    // spin up the commandChannel handlers
    for i := 0; i < *workersFlag; i++ {
        go func() {
            for command := range commandChannel {
                responseChannel <- ProcessCommand(command, *timeoutFlag)
                waitgrp.Done()
            }
        }()
    }

    // spin up the responseChannel handler
    go func() {
        for {
            select {
                case response := <-responseChannel:
                    writer.Write([]string{response.result, response.mode, response.host, response.port, response.reason})
                    writer.Flush()
                case <-time.After(30 * time.Second):
                    fmt.Fprintln(os.Stderr, "timed out")
                    os.Exit(1)
            }
        }
    }()

    // process each line from standard input and issue command
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
            case "ftp", "https", "imap", "pop3", "smtp":
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
                commandChannel <- Command{mode, host.String(), port}
            }
        } else {
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "scanning", mode, spec, port)
            }
            waitgrp.Add(1)
            commandChannel <- Command{mode, spec, port}
        }
    }

    // wait for all workers to finish and clean up
    waitgrp.Wait()
    close(commandChannel)
    close(responseChannel)
    writer.Flush()
}
