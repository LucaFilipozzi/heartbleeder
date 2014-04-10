package main

import (
    "net"
	"fmt"
	"os"
	"strings"
    "io/ioutil"
	"time"
    "sync"

	"heartbleeder/tls"
)

const workers int = 512

func is_vulnerable(host string) bool {
    if !strings.Contains(host, ":") {
        host += ":443"
    }

    dialer := &net.Dialer{
        Timeout: 1 * time.Second,
    }

	c, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
        return false
	}
    defer c.Close()

	err = c.WriteHeartbeat(1, nil)
	if err == tls.ErrNoHeartbeat {
        return false
	}
	if err != nil {
		fmt.Println("UNKNOWN - Heartbeat enabled, but there was an error writing the payload:", err)
        return false
	}

	readErr := make(chan error)
	go func() {
		_, _, err := c.ReadHeartbeat()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
            return true
		}
        return false
	case <-time.After(1 * time.Second):
        return false
	}
}

func worker(test chan string, wg *sync.WaitGroup) {
    for host := range test {
        if is_vulnerable(host) {
            fmt.Println(host, "is vulnerable")
        }
        wg.Done()
    }
}

func main() {
    // Read in the hosts to test
    file, err := ioutil.ReadFile(os.Args[1])
    if err != nil {
        os.Exit(1)
    }
    lines := strings.Split(string(file), "\n")

    // Set up the wait group
    wg := &sync.WaitGroup{}
    wg.Add(len(lines))

    // The channel we will pass info on
    test := make(chan string, 2 * workers)

    // Spin up the workers
    for i := 0; i < workers; i++ {
        go worker(test, wg)
    }

    // Scanning
    for _,host := range lines {
        test <- host
    }

    wg.Wait()
    close(test)
}
