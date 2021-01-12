package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	seenDests       = make(map[string]int)
	shallDests      = make(map[string]int)
	shallDestsNames = make(map[string]string)
	shallDestsCmd   = make(map[string]string)
	keepRunning     = true
)

func main() {
	/* parameters */
	device := flag.String("i", "en2", "interface name to snoop traffic on")
	learn := flag.Bool("l", false, "'learn'-mode, save this as starting file")
	promiscuous := flag.Bool("p", false, "enable promiscuous mode for interface card")
	timeout := flag.Duration("t", 15*time.Second, "default time for capturing, set down for learn-mode")
	fileName := flag.String("f", "", "file for connection table, e.g. learn-mode output")
	flag.Parse()

	/* read wished capture */
	if !*learn {
		if *fileName == "" {
			log.Fatal("No filename given for connection table")
		}
		readFile(*fileName)
	}

	/* open device */
	handle, err := pcap.OpenLive(*device, 128, *promiscuous, *timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	/* signal loop stop  */
	go func() {
		time.Sleep(*timeout)
		keepRunning = false
	}()

	/* packet reading loop */
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		sumPacket(packet)
		if !keepRunning {
			break
		}
	}

	/* when learning mode, print out the bucket */
	if *learn {
		for k, v := range seenDests {
			fmt.Printf("%s=%d\n", k, v)
		}
	}

	/* compare seen to must destinations, print check mk compatible local check if
	we have a match, else warning / critical
	*/

	for tuple, bytes := range shallDests {
		var serviceName string

		/* Check for complete service string */
		if bytesSeen, ok := seenDests[tuple]; ok {

			if destName, ok := shallDestsNames[tuple]; ok {
				serviceName = destName
			}

			if bytesSeen < bytes {
				fmt.Printf("1 %s -  %s  missing (%d/%d) bytes\n", tuple, serviceName, bytesSeen, bytes)
			} else {
				fmt.Printf("0 %s - %s fine (%d/%d) bytes\n", tuple, serviceName, bytesSeen, bytes)
			}
		} else {
			fmt.Printf("2 %s - %s zero (0/%d) bytes\n", tuple, serviceName, bytes)
			if _, exists := shallDestsCmd[tuple]; exists {
				if shallDestsCmd[tuple] != "" {
					extraArgs := strings.Split(shallDestsCmd[tuple], " ")
					cmd := exec.Command(extraArgs[0], extraArgs[1:]...)

					err = cmd.Run()
					if err != nil {
						log.Println("Executing error ", extraArgs[0], err)
					}

				}
			}
		}

	}

}

/* move down the layers
and count bytes per destination
*/
func sumPacket(packet gopacket.Packet) {
	/* probe for ipv4 layer */
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	/* exit early */
	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp != nil {
			hostPort := fmt.Sprintf("TCP:%s:%d", ip.DstIP.String(), tcp.DstPort)
			hostOnly := fmt.Sprintf("TCP:%s:0", ip.DstIP.String())
			seenDests[hostPort] += int(ip.Length)
			seenDests[hostOnly] += int(ip.Length)
			return
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil {
			hostPort := fmt.Sprintf("UDP:%s:%d", ip.DstIP.String(), udp.DstPort)
			hostOnly := fmt.Sprintf("UDP:%s:0", ip.DstIP.String())
			seenDests[hostPort] += int(ip.Length)
			seenDests[hostOnly] += int(ip.Length)
			return
		}
	}

}

func readFile(fileName string) {

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parsed := strings.Split(scanner.Text(), "=")
		if len(parsed) < 2 {
			continue
		}
		i, err := strconv.Atoi(parsed[1])
		if err == nil {
			shallDests[parsed[0]] = i
			if len(parsed) >= 3 && parsed[2] != "" {
				shallDestsNames[parsed[0]] = parsed[2]
			}

			/* handler, e.g. bash restart script */
			if len(parsed) >= 4 {
				shallDestsCmd[parsed[0]] = parsed[3]
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}
