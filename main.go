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
	"strconv"
	"strings"
	"time"
)

var (
	seenDests   = make(map[string]int)
	shallDests  = make(map[string]int)
	keepRunning = false
)

func main() {

	device := flag.String("i", "en2", "interface name to snoop traffic on")
	learn := flag.Bool("l", false, "'learn'-mode, save this as starting file")
	promiscuous := flag.Bool("p", false, "promiscuous mode for interface card")
	timeout := flag.Duration("t", 10 * time.Second, "default time to capture packets")
	fileName := flag.String("f", "", "")
	flag.Parse()

	/* read wished capture */
	if !*learn { readFile(*fileName) }

	/* open device */
	handle, err := pcap.OpenLive(*device, 128, *promiscuous, *timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	/* signal loop stop  */
	go func() {
		time.Sleep(time.Second * 10)
		keepRunning = false
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		sumPacket(packet)
		if !keepRunning {
			break
		}
	}

	if *learn {
		for k, v := range seenDests {
			fmt.Printf("%s=%d\n", k, v)
		}
	}

	/* compare seen to must destinations, print check mk compatible local check if
	we have a match, else warning / critical
	 */

	for tuple, bytes := range shallDests {
		if bytesSeen, ok := seenDests[tuple]; ok {
			if bytesSeen < bytes {
				fmt.Printf("2 %s - , (%d/%d) bytes\n", tuple, bytesSeen, bytes)
			} else {
				fmt.Printf("0 %s - (%d/%d) bytes\n", tuple, bytesSeen, bytes)
			}
		} else {
			fmt.Printf("1 %s - (0/%d) bytes\n", tuple, bytes)
		}
	}

}

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
			seenDests[hostPort] += int(ip.Length)
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil {
			hostPort := fmt.Sprintf("UDP:%s:%d", ip.DstIP.String(), udp.DstPort)
			seenDests[hostPort] += int(ip.Length)
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
		if len(parsed) != 2  {
			continue
		}
		i, err := strconv.Atoi(parsed[1])
		if err == nil {
			shallDests[parsed[0]] = i
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}
