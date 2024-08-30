package main

import (
	"bufio"
	"flag"
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
	debugptr := flag.Bool("D", false, "Enable Debug output")
	clrptr := flag.Bool("c", false, "Print Debug output in color")
	msptr := flag.Bool("ms", false, "ignore anything < 1ms")
	flag.Parse()
	debug := *debugptr
	msonly := *msptr

	var Reset = ""
	var Red = ""
	var Green = ""
	var Yellow = ""
	var Blue = ""
	var Magenta = ""
	//var Cyan = ""
	var Gray = ""
	var White = ""
	if *clrptr {
		Reset = "\033[0m"
		Red = "\033[31m"
		Green = "\033[32m"
		Yellow = "\033[33m"
		Blue = "\033[34m"
		Magenta = "\033[35m"
		//Cyan = "\033[36m"
		Gray = "\033[37m"
		White = "\033[97m"
	}

	var reqs []dnsreq

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		inp := scanner.Text()
		re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\+.* [^A]*(?P<isreq>A+\?) ([_\w\.\-\d]+) `)
		m := re.FindStringSubmatch(inp)
		if len(m) == 0 {
			re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\+ (?P<isreq>PTR\?) ([_\w\.\-\d]+) `)
			m = re.FindStringSubmatch(inp)
		}
		if len(m) == 0 {
			re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\+.* (?P<isreq>SRV\?) ([_\w\.\-\d]+) `)
			m = re.FindStringSubmatch(inp)
		}
		if len(m) > 0 {
			myreq, _ := strconv.Atoi(m[2])
			var hostname string
			if m[4][len(m[4])-1:] == "." {
				hostname = m[4][:len(m[4])-1]
			} else {
				hostname = m[4]
			}
			if debug {
				fmt.Println(Green+"Got request "+White, myreq, Green+"for "+Gray, hostname, Green+"at ", m[1], ": "+Reset, inp)
			}
			t1, _ := time.Parse(time.TimeOnly, m[1])
			item := dnsreq{reqtime: t1, recno: myreq, host: hostname}
			reqs = append(reqs, item)
		} else {
			re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\*`)
			m := re.FindStringSubmatch(inp)
			if len(m) == 0 {
				re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\D*.* A \d`)
				m = re.FindStringSubmatch(inp)
			}
			if len(m) == 0 {
				re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+)\D*.* PTR [\w\d]`)
				m = re.FindStringSubmatch(inp)
			}
			if len(m) > 0 {
				myreq, _ := strconv.Atoi(m[2])
				if debug {
					fmt.Println(Blue+"Found response to req"+White, myreq, Green+"at", m[1], ":"+Reset, inp)
				}
				t1, _ := time.Parse(time.TimeOnly, m[1])
				l := len(reqs)
				found := false
				for a := 0; a < l; a++ {
					if reqs[a].recno == myreq {
						delta := t1.Sub(reqs[a].reqtime)
						if msonly {
							if delta.Milliseconds() != 0 {
								fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta.Round(time.Millisecond))
							}
						} else {
							fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta)
						}
						reqs = append(reqs[:a], reqs[a+1:]...)
						a = l + 1
						found = true
					}
				}
				if !found {
					if debug {
						fmt.Println(Yellow+"Didn't find matching request for "+Reset, myreq)
					}
				}
			} else {
				re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+) ServFail`)
				m := re.FindStringSubmatch(inp)
				if len(m) > 0 {
					myreq, _ := strconv.Atoi(m[2])
					if debug {
						fmt.Println(Magenta+"Found SERVFAIL for req"+White, myreq, Magenta+"at", m[1], ":"+Reset, inp)
					}
					t1, _ := time.Parse(time.TimeOnly, m[1])
					l := len(reqs)
					found := false
					for a := 0; a < l; a++ {
						if reqs[a].recno == myreq {
							delta := t1.Sub(reqs[a].reqtime)
							if msonly {
								if delta.Milliseconds() != 0 {
									fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta.Round(time.Millisecond))
								}
							} else {
								fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta)
							}
							reqs = append(reqs[:a], reqs[a+1:]...)
							a = l + 1
							found = true
						}
					}
					if !found {
						if debug {
							fmt.Println(Yellow+"Didn't find matching request for "+Reset, myreq)
						}
					}
				} else {
					re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+) NXDomain`)
					m := re.FindStringSubmatch(inp)
					if len(m) > 0 {
						myreq, _ := strconv.Atoi(m[2])
						if debug {
							fmt.Println(Magenta+"Found NXDomain for req"+White, myreq, Magenta+"at", m[1], ":"+Reset, inp)
						}
						t1, _ := time.Parse(time.TimeOnly, m[1])
						l := len(reqs)
						found := false
						for a := 0; a < l; a++ {
							if reqs[a].recno == myreq {
								delta := t1.Sub(reqs[a].reqtime)
								if msonly {
									if delta.Milliseconds() != 0 {
										fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta.Round(time.Millisecond))
									}
								} else {
									fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta)
								}
								reqs = append(reqs[:a], reqs[a+1:]...)
								a = l + 1
								found = true
							}
						}
						if !found {
							if debug {
								fmt.Println(Yellow+"Didn't find matching request for "+Reset, myreq)
							}
						}
					} else {
						re := regexp.MustCompile(`^(?P<mytime>[\d:\.]+) IP.*: (?P<myreqno>\d+) .* CNAME `)
						m := re.FindStringSubmatch(inp)
						if len(m) > 0 {
							myreq, _ := strconv.Atoi(m[2])
							if debug {
								fmt.Println(Magenta+"Found CNAME for req"+White, myreq, Magenta+"at", m[1], ":"+Reset, inp)
							}
							t1, _ := time.Parse(time.TimeOnly, m[1])
							l := len(reqs)
							found := false
							for a := 0; a < l; a++ {
								if reqs[a].recno == myreq {
									delta := t1.Sub(reqs[a].reqtime)
									if msonly {
										if delta.Milliseconds() != 0 {
											fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta.Round(time.Millisecond))
										}
									} else {
										fmt.Println("DNS Delay for req", myreq, "on", reqs[a].host, "is", delta)
									}
									reqs = append(reqs[:a], reqs[a+1:]...)
									a = l + 1
									found = true
								}
							}
							if !found {
								if debug {
									fmt.Println(Yellow+"Didn't find matching request for "+Reset, myreq)
								}
							}
						} else {
							if debug {
								fmt.Println(Red+"Ignored packet"+White, inp, Reset)
							}
						}

					}
				}
			}
		}
	}
	if scanner.Err() != nil {
		log.Println(scanner.Err())
	}
}
