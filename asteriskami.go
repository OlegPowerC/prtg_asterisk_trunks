package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

type result struct {
	Channel     string `xml:"channel"`
	Value       string `xml:"value"`
	Valuelookup string `xml:"ValueLookup"`
}

type prtgbody struct {
	XMLName xml.Name `xml:"prtg"`
	Res     []result `xml:"result"`
}

type amiparams struct {
	AsteriskIP   string
	AsteriskPort string
	AMIUser      string
	AMIPassword  string
}

type siptrunkregstatus struct {
	SipUsername  string
	SipRegStatus string
}

func RespToMap(stresp string) map[string]string {
	var rmap map[string]string
	rmap = make(map[string]string, 0)
	ass := strings.Split(stresp, "\r\n")
	for _, assentry := range ass {
		assformap := strings.Split(assentry, ":")
		if len(assformap) == 2 {

			rmap[assformap[0]] = strings.TrimSpace(assformap[1])
		}
	}
	return rmap
}

func main() {
	username := flag.String("u", "prtg", "asterisk AMI username")
	passwd := flag.String("p", "prtg", "aterisk AMI password")
	aaip := flag.String("i", "", "aterisk IP address")
	aaport := flag.String("dp", "5038", "asterisk MII port, default 5038")
	flag.Parse()

	var ststat []siptrunkregstatus
	sm := amiparams{*aaip, *aaport, *username, *passwd}
	conn, err := net.Dial("tcp", sm.AsteriskIP+":"+sm.AsteriskPort)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	scanner := bufio.NewScanner(conn)

	AuthStr := "Action: login\r\nUsername: " + sm.AMIUser + "\r\n" + "Secret: " + sm.AMIPassword + "\r\nEvents: off\r\nActionID: 23456063340\r\n\r\n"

	SipRegistryStr := "Action: SIPshowregistry\r\nActionID: 23456063340\r\n\r\n"

	LogooffStr := "Action: logoff\r\n\r\n"

	for scanner.Scan() {
		conn.Write([]byte(AuthStr))
		break
	}

	scanner2 := bufio.NewScanner(conn)
	scanner2.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {

		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		if i := strings.Index(string(data), "\r\n\r\n"); i >= 0 {
			return i + len("\r\n\r\n"), data[0 : i+len("\r\n\r\n")], nil
		}

		if atEOF {
			return len(data), data, nil
		}

		return
	})

	scanner2.Scan()
	AuthRespT := scanner2.Text()

	EventListFlag := false

	authrespm := RespToMap(AuthRespT)

	if authrespm["Message"] == "Authentication accepted" {
		conn.Write([]byte(SipRegistryStr))
		for scanner2.Scan() {
			respt := scanner2.Text()
			sipregm := RespToMap(respt)

			if val, ok := sipregm["ActionID"]; ok {
				if val == "23456063340" {
					if val, ok := sipregm["EventList"]; ok {
						if val == "start" {
							EventListFlag = true
							continue
						}
					}
				}
			}

			if val, ok := sipregm["ActionID"]; ok {
				if val == "23456063340" {
					if val, ok := sipregm["EventList"]; ok {
						if val == "Complete" {
							break
						}
					} else {

						if val, ok := sipregm["ActionID"]; ok {
							if val == "23456063340" {
								if val, ok := sipregm["EventList"]; ok {
									if val == "Complete" {
										break
									}
								} else {

									if EventListFlag {
										if val, ok := sipregm["Event"]; ok {
											if val == "RegistryEntry" {
												st := sipregm["State"]
												un := sipregm["Username"]
												ststat = append(ststat, siptrunkregstatus{un, st})
											}
										}
									}

								}
							}
						}
					}
				}
			}
		}
	}

	conn.Write([]byte(LogooffStr))
	scanner2.Scan()
	conn.Close()

	var rd1 []result

	for _, rres := range ststat {
		itstat := 0
		if rres.SipRegStatus == "Registered" {
			itstat = 1
		}
		rd1 = append(rd1, result{rres.SipUsername, strconv.Itoa(itstat), "Asterisk"})
	}

	mt1 := &prtgbody{Res: rd1}
	bolB, _ := xml.Marshal(mt1)
	fmt.Println(string(bolB))
}
