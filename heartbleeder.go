package main

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/ziutek/utils/netaddr"

    "github.com/LucaFilipozzi/heartbleeder/tls"
)

const workers int = 512

func test_for_heartbleed(host string) {
    dialer := &net.Dialer{
        Timeout: 1 * time.Second,
    }

    c, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
    if err != nil {
        fmt.Fprintln(os.Stdout, "N", host) // not vulnerable - no connection
        return
    }
    defer c.Close()

    err = c.WriteHeartbeat(1, nil)
    if err == tls.ErrNoHeartbeat {
        fmt.Fprintln(os.Stdout, "N", host) // not vulnerable - connection but no heartbeat
        return
    }
    if err != nil {
        fmt.Fprintln(os.Stdout, "E", host, err) // error - connection and heartbeat but error writing payload
        return
    }

    readErr := make(chan error)
    go func() {
        _, _, err := c.ReadHeartbeat()
        readErr <- err
    }()

    select {
        case err := <-readErr:
            if err == nil {
                fmt.Fprintln(os.Stdout, "Y", host) // vulernable - successfully read process memory!!
            } else {
                fmt.Fprintln(os.Stdout, "N", host) // not vulnerable - unsuccessfully read process memory
            }
        case <-time.After(1 * time.Second):
            fmt.Fprintln(os.Stdout, "N", host) // not vulnerable - connection timed out
    }
}

func worker(channel chan string, wg *sync.WaitGroup) {
    for host := range channel {
        test_for_heartbleed(host)
        wg.Done()
    }
}

func main() {
    // set up the channel for worker communication
    channel := make(chan string, 2 * workers)

    // set up a wait group to track the workers
    waitgrp := &sync.WaitGroup{}

    // spin up the workers
    for i := 0; i < workers; i++ {
        go worker(channel, waitgrp)
    }

    // scan each hostname or CIDR address read from stdin
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        if !strings.Contains(line, ":") {
            line += ":443"
        }
        if strings.Contains(line, "/") {
            parts := strings.Split(line, ":")
            cidr := parts[0]
            port := parts[1]
            ip, ipnet, err := net.ParseCIDR(cidr)
            if err != nil {
                fmt.Fprintln(os.Stderr, "skipping", line, err)
                continue
            }
            fmt.Fprintln(os.Stderr, "scanning", line)
            for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ip = netaddr.IPAdd(ip, 1) {
                waitgrp.Add(1)
                channel <- ip.String() + ":" + port
            }
        } else {
            fmt.Fprintln(os.Stderr, "scanning", line)
            waitgrp.Add(1)
            channel <- line
        }
    }

    // wait for all workers to finish
    waitgrp.Wait()
    close(channel)
}
