package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"
)

type dnsreq struct {
	reqtime time.Time
	recno   int
	host    string
}

func main() {
	debug := false
	var reqs []dnsreq

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		inp := scanner.Text()
		re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\+ [^A]*(?P<isreq>A+\?) ([\w\.\-\d]+) `)
		m := re.FindStringSubmatch(inp)
		if len(m) > 0 {
			myreq, _ := strconv.Atoi(m[2])
			var hostname string
			if m[4][len(m[4])-1:] == "." {
				hostname = m[4][:len(m[4])-1]
			} else {
				hostname = m[4]
			}
			if debug {
				fmt.Println("found request for ", hostname, "at ", m[1], ": ", inp)
			}
			t1, _ := time.Parse(time.TimeOnly, m[1])
			item := dnsreq{reqtime: t1, recno: myreq, host: hostname}
			reqs = append(reqs, item)
		} else {
			re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\*`)
			m := re.FindStringSubmatch(inp)
			if len(m) > 0 {
				myreq, _ := strconv.Atoi(m[2])
				if debug {
					fmt.Println("found response to req", myreq, "at", m[1], ":", inp)
				}
				t1, _ := time.Parse(time.TimeOnly, m[1])
				l := len(reqs)
				found := false
				for a := 0; a < l; a++ {
					if reqs[a].recno == myreq {
						delta := t1.Sub(reqs[a].reqtime)
						fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta)
						reqs = append(reqs[:a], reqs[a+1:]...)
						a = l + 1
						found = true
					}
				}
				if !found {
					if debug {
						fmt.Println("Didn't find matching request for ", myreq)
					}
				}
			} else {
				re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+) ServFail`)
				m := re.FindStringSubmatch(inp)
				if len(m) > 0 {
					myreq, _ := strconv.Atoi(m[2])
					if debug {
						fmt.Println("Found SERVFAIL for req ", myreq, " at ", m[1], ": ", inp)
					}
					t1, _ := time.Parse(time.TimeOnly, m[1])
					l := len(reqs)
					found := false
					for a := 0; a < l; a++ {
						if reqs[a].recno == myreq {
							delta := t1.Sub(reqs[a].reqtime)
							fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta)
							reqs = append(reqs[:a], reqs[a+1:]...)
							a = l + 1
							found = true
						}
					}
					if !found {
						if debug {
							fmt.Println("Didn't find matching request for ", myreq)
						}
					}
				}
				if debug {
					fmt.Println("Ignored packet")
				}
			}
		}
	}
	if scanner.Err() != nil {
		log.Println(scanner.Err())
	}
}
