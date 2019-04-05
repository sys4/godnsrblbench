package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"log"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	fverbose     bool
	enumerateDev bool
	devName      string
	captureIP    string
	domainSuffix string
	rblserverdef string
	err      error
	handle   *pcap.Handle
	InetAddr string
	SrcIP    string
	DstIP    string
)

func init() {
	flag.StringVar(&devName, "i", "iwn0", "Interface for packet capture")
	flag.StringVar(&captureIP, "c", "8.8.8.8", "IP address of the dns server to capture messages from")
	flag.StringVar(&domainSuffix, "s", "", "DNS Suffix used to filter DNS query data (name of a RBLDNS provider)")
	flag.StringVar(&rblserverdef, "r", "", "List of DNS RBL Provider to test. Format '<ip>:<port>/<domain, ...'")	
	flag.BoolVar(&enumerateDev, "l", false, "Enumerate network devices")
	flag.BoolVar(&fverbose, "v", false, "Verbose log output")
}

func dnsQuery(query, dnsserver string, fverbose bool) {
	if fverbose {
		fmt.Println("Query     :" + query)
		fmt.Println("DNS-Server:" + dnsserver)
	}
	start := time.Now()
	conn, err := dns.DialTimeout("udp", dnsserver, time.Second)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	go func() {
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(query), dns.TypeA)
		conn.WriteMsg(msg)
	}()

	msg, err := conn.ReadMsg()
	if err != nil {
		panic(err)
	}

	var answer = ""
	if len(msg.Answer) != 0 {
		if msg.Answer[0] != nil {
			answer = dns.Field(msg.Answer[0], 1)
			// fmt.Println("Answer :", answer)
			// fmt.Printf("%#v\n", msg.Answer[0])

			// fmt.Println("Type   :", msg.Answer[0].Rrtype)
			// fmt.Println("Type   :", msg.Answer[0].Rdata)
		}
		duration := time.Since(start).Seconds()
		if fverbose {
			fmt.Printf("Answer %s from %s received in %f seconds\n", answer, dnsserver, duration)
		}
		log.Printf("Answer: | %s | %s | %s | %f |\n", query, answer, dnsserver, duration)
	} else {
		duration := time.Since(start).Seconds()
		log.Printf("Answer: | %s | %s | %s | %f |\n", query, "--", dnsserver, duration)
	}
}

func main() {
	flag.Parse()

	//rblserverdef := "8.8.8.8:53/spamhouse.com,1.1.1.1:53/abusix.de,9.9.9.9:53/nixspam.de"
	rblservers := strings.Split(rblserverdef, ",")
	if fverbose {
		fmt.Println("DNS RBL Servers used:" + strings.Join(rblservers,","))
	}

	logwriter, e := syslog.New(syslog.LOG_NOTICE, "dnsrblbench")
	if e == nil {
		log.SetOutput(logwriter)
	}

	if enumerateDev {
		devices, devErr := pcap.FindAllDevs()
		if devErr != nil {
			log.Fatal(devErr)
		}

		for _, device := range devices {
			fmt.Println("Device: ", device.Name)
		}
		os.Exit(0)
	}

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS

	var payload gopacket.Payload

	// Open device
	handle, err = pcap.OpenLive(devName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "udp and port 53 and host " + captureIP
	if fverbose {
		fmt.Println("PCAP Filter: ", filter)
	}
	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}

		err = parser.DecodeLayers(data, &decodedLayers)
		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
			case layers.LayerTypeDNS:
				dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)

				if (dns.Questions[0].Type == 1) || (dns.Questions[0].Type == 28) {
					if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
						if fverbose {
							fmt.Println(">>")
							fmt.Println("    DNS Answer found")
						}

						for _, dnsQuestion := range dns.Questions {
							qname := string(dnsQuestion.Name)

							t := time.Now()
							timestamp := t.Format(time.RFC3339)
							if fverbose {
								fmt.Println("    Time: ", timestamp)
								fmt.Println("    DNS OpCode:       ", strconv.Itoa(dnsOpCode))
								fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
								fmt.Println("    DNS # Answers:    ", strconv.Itoa(dnsANCount))
								fmt.Println("    DNS QName:        ", qname)
								fmt.Println("    DNS Type:         ", dnsQuestion.Type)
								fmt.Println("    DNS Endpoints:    ", SrcIP, DstIP)

								if dnsANCount > 0 {
									for _, dnsAnswer := range dns.Answers {
										if dnsAnswer.IP.String() != "<nil>" {
											fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
										}
									}
								}
								if strings.HasSuffix(qname, domainSuffix) {
									bname := strings.TrimSuffix(qname, domainSuffix)
									for _, rblserver := range rblservers {
										rblservice := strings.Split(rblserver, "/")
										go dnsQuery(bname+rblservice[1], rblservice[0], fverbose)
									}
								}

							}
						}
					}
				}

			}
		}

		if err != nil {
			log.Println("  Error encountered:", err)
		}
	}
}
