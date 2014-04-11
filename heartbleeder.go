package main

import (
    "bufio"
    "encoding/csv"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/mikioh/ipaddr"
    "github.com/LucaFilipozzi/heartbleeder/tls"
)

type Command struct {
    mode string
    target string
}

type Response struct {
    rval string
    rstr string
}

func test_for_heartbleed(target string, timeout time.Duration) (response Response) {
    dialer := &net.Dialer{Timeout: timeout}

    c, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{InsecureSkipVerify: true})
    if err != nil {
        return Response{"N", "connection refused"}
    }
    defer c.Close()

    err = c.WriteHeartbeat(1, nil)
    if err == tls.ErrNoHeartbeat {
        return Response{"N", "heartbeat disabled"}
    }
    if err != nil {
        return Response{"E", "error injecting payload"}
    }

    readErr := make(chan error)
    go func() {
        _, _, err := c.ReadHeartbeat()
        readErr <- err
    }()

    select {
        case err := <-readErr:
            if err == nil {
                return Response{"Y", "heartbeat enabled and vulnerable!"}
            } else {
                return Response{"N", "heartbeat enabled but not vulnerable"}
            }
        case <-time.After(timeout):
            return Response{"N", "heartbeat enabled but timed out after payload injection"}
    }
}

func worker(channel chan Command, wg *sync.WaitGroup, timeout time.Duration, verbose bool, writer *csv.Writer) {
    record := make([]string,3)
    for command := range channel {
        if verbose {
            fmt.Fprintln(os.Stderr, "checking", command.target)
        }
        response := test_for_heartbleed(command.target, timeout)
        record[0] = response.rval
        record[1] = command.target
        record[2] = response.rstr
        writer.Write(record)
        wg.Done()
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
        go worker(channel, waitgrp, *timeoutFlag, *verboseFlag, writer)
    }

    // scan each hostname or CIDR address read from stdin
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Count(line, ":") != 2 {
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "skipping", line, "does not parse correctly")
            }
            continue
        }

        parts := strings.Split(line, ":")
        mode := parts[0]
        spec := parts[1]
        port := parts[2]

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

            for _, host := range prefix.Hosts(ip) {
                target := host.String() + ":" + port
                if *verboseFlag {
                    fmt.Fprintln(os.Stderr, "scanning", target)
                }
                waitgrp.Add(1)
                channel <- Command{mode, target}
            }

        } else {

            target := spec + ":" + port
            if *verboseFlag {
                fmt.Fprintln(os.Stderr, "scanning", target)
            }
            waitgrp.Add(1)
            channel <- Command{mode, target}

        }
    }

    // wait for all workers to finish
    waitgrp.Wait()
    close(channel)

    writer.Flush()

}
