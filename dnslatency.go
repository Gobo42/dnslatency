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
	dserver string
}

type dnsserverrep struct {
	server string
	rep    int
}

var debug bool
var extradebug bool
var Reset = ""
var Red = ""
var Green = ""
var Yellow = ""
var Blue = ""
var Magenta = ""
var Cyan = ""
var Gray = ""
var White = ""

func modrep(inrep []dnsserverrep, inserver string, inmodrep int) []dnsserverrep {
	if extradebug {
		fmt.Println(Cyan+"Adding", inmodrep, "to"+White, inserver+Cyan+"'s rep"+Reset)
	}
	found := false
	for a := 0; a < len(inrep); a++ {
		if inrep[a].server == inserver {
			inrep[a].rep += inmodrep
			found = true
			if extradebug {
				fmt.Println(Cyan+"Found"+White, inserver, Cyan+". New rep is", inrep[a].rep, Reset)
			}
		}
	}
	if !found {
		if extradebug {
			fmt.Println(Cyan+"Not found. adding"+White, inserver, Cyan+"with rep", inmodrep, Reset)
		}
		inrep = append(inrep, dnsserverrep{server: inserver, rep: inmodrep})
	}
	return inrep
}

func checkrep(inrep []dnsserverrep, val int) (result bool, servernames []string) {
	result = false
	for a := 0; a < len(inrep); a++ {
		if inrep[a].rep > val {
			result = true
			servernames = append(servernames, inrep[a].server)
		}
	}
	return
}

func main() {
	debugptr := flag.Bool("D", false, "Enable Debug output")
	extradebugptr := flag.Bool("DD", false, "Extra Debug")
	clrptr := flag.Bool("c", false, "Print Debug output in color")
	msptr := flag.Bool("ms", false, "ignore anything < 1ms")
	repptr := flag.Int("rep", 0, "Enable DNS server reputation for outstanding requests. Requires value")
	showsvrptr := flag.Bool("v", false, "show the DNS server call was made to")
	flag.Parse()
	debug = *debugptr
	msonly := *msptr
	dnsrep := *repptr
	showsvr := *showsvrptr
	extradebug = *extradebugptr
	if extradebug {
		debug = true
	}
	if *clrptr {
		Reset = "\033[0m"
		Red = "\033[31m"
		Green = "\033[32m"
		Yellow = "\033[33m"
		Blue = "\033[34m"
		Magenta = "\033[35m"
		Cyan = "\033[36m"
		Gray = "\033[37m"
		White = "\033[97m"
	}
	var reqs []dnsreq
	var dnsrepdb []dnsserverrep

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		inp := scanner.Text()
		srvre := regexp.MustCompile(` ([_\w\d\.\-]+)\.domain[ :]`)
		srvm := srvre.FindStringSubmatch(inp)
		if len(srvm) == 0 {
			srvre := regexp.MustCompile(` ([_\w\d\.\-]+)\.53[ :]`)
			srvm = srvre.FindStringSubmatch(inp)
		}
		var dnsserver string
		if len(srvm) == 0 {
			if debug {
				fmt.Println(Red+"Couldn't determine DNS server: "+White, inp, Reset)
			}
			dnsserver = "unknown"
		} else {
			dnsserver = srvm[1]
			if debug {
				fmt.Println(Cyan+"Got DNS Server "+Yellow, dnsserver, Reset)
			}
		}
		if dnsrep != 0 {
			var servers []string
			check, servers := checkrep(dnsrepdb, dnsrep)
			if check {
				for a := 0; a < len(servers); a++ {
					if debug {
						fmt.Println(Red+"DNS Server"+Yellow, servers[a], Red+"Has not replied to more than", dnsrep, "requests", Reset)
					} else {
						fmt.Println("Server", servers[a], "is over the threshold of outstanding requests")
					}

				}
			}
			if extradebug {
				fmt.Println(Cyan+"dnsrepdb = "+White, dnsrepdb, Reset)
			}
		}
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
			item := dnsreq{reqtime: t1, recno: myreq, host: hostname, dserver: dnsserver}
			reqs = append(reqs, item)
			if dnsrep != 0 {
				dnsrepdb = modrep(dnsrepdb, dnsserver, 1)
			}
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
					fmt.Println(Blue+"Found response to req "+White, myreq, Green+"at", m[1], ":"+Reset, inp)
				}
				t1, _ := time.Parse(time.TimeOnly, m[1])
				l := len(reqs)
				found := false
				for a := 0; a < l; a++ {
					if (reqs[a].recno == myreq) && (reqs[a].dserver == dnsserver) {
						delta := t1.Sub(reqs[a].reqtime)
						if msonly {
							if delta.Milliseconds() != 0 {
								fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
								if showsvr {
									fmt.Print(" from server", dnsserver)
								}
								fmt.Println(" is", delta.Round(time.Millisecond))
							}
						} else {
							fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
							if showsvr {
								fmt.Print(" from server", dnsserver)
							}
							fmt.Println(" is", delta)
						}
						reqs = append(reqs[:a], reqs[a+1:]...)
						a = l + 1
						found = true
						if dnsrep != 0 {
							dnsrepdb = modrep(dnsrepdb, dnsserver, -1)
						}
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
						fmt.Println(Magenta+"Found SERVFAIL for req "+White, myreq, Magenta+"at", m[1], ":"+Reset, inp)
					}
					t1, _ := time.Parse(time.TimeOnly, m[1])
					l := len(reqs)
					found := false
					for a := 0; a < l; a++ {
						if (reqs[a].recno == myreq) && (reqs[a].dserver == dnsserver) {
							delta := t1.Sub(reqs[a].reqtime)
							if msonly {
								if delta.Milliseconds() != 0 {
									fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
									if showsvr {
										fmt.Print(" from server", dnsserver)
									}
									fmt.Println(" is", delta.Round(time.Millisecond))
								}
							} else {
								fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
								if showsvr {
									fmt.Print(" from server", dnsserver)
								}
								fmt.Println(" is", delta)
							}
							reqs = append(reqs[:a], reqs[a+1:]...)
							a = l + 1
							found = true
							if dnsrep != 0 {
								dnsrepdb = modrep(dnsrepdb, dnsserver, -1)
							}
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
							fmt.Println(Magenta+"Found NXDomain for req "+White, myreq, Magenta+"at", m[1], ":"+Reset, inp)
						}
						t1, _ := time.Parse(time.TimeOnly, m[1])
						l := len(reqs)
						found := false
						for a := 0; a < l; a++ {
							if (reqs[a].recno == myreq) && (reqs[a].dserver == dnsserver) {
								delta := t1.Sub(reqs[a].reqtime)
								if msonly {
									if delta.Milliseconds() != 0 {
										fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
										if showsvr {
											fmt.Print(" from server", dnsserver)
										}
										fmt.Println(" is", delta.Round(time.Millisecond))
									}
								} else {
									fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
									if showsvr {
										fmt.Print(" from server", dnsserver)
									}
									fmt.Println(" is", delta)
								}
								reqs = append(reqs[:a], reqs[a+1:]...)
								a = l + 1
								found = true
								if dnsrep != 0 {
									dnsrepdb = modrep(dnsrepdb, dnsserver, -1)
								}
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
								fmt.Println(Magenta+"Found CNAME for req "+White, myreq, Magenta+"at", m[1], ":"+Reset, inp)
							}
							t1, _ := time.Parse(time.TimeOnly, m[1])
							l := len(reqs)
							found := false
							for a := 0; a < l; a++ {
								if (reqs[a].recno == myreq) && (reqs[a].dserver == dnsserver) {
									delta := t1.Sub(reqs[a].reqtime)
									if msonly {
										if delta.Milliseconds() != 0 {
											fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
											if showsvr {
												fmt.Print(" from server", dnsserver)
											}
											fmt.Println(" is", delta.Round(time.Millisecond))
										}
									} else {
										fmt.Print("DNS Delay for req ", myreq, " on ", reqs[a].host)
										if showsvr {
											fmt.Print(" from server", dnsserver)
										}
										fmt.Println(" is", delta)
									}
									reqs = append(reqs[:a], reqs[a+1:]...)
									a = l + 1
									found = true
									if dnsrep != 0 {
										dnsrepdb = modrep(dnsrepdb, dnsserver, -1)
									}
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
