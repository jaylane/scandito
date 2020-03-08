package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
)

var host, ports string
var numWorkers uint

func init() {
	flag.StringVar(&host, "host", "scanme.nmap.org", "a host address to scan")
	flag.StringVar(&ports, "ports", "1-1024", "ports to scan, can be a range 1-100 a comma separated list 1,2,3 or a single port")
	flag.UintVar(&numWorkers, "workers", 100, "number of concurrent workers")
	flag.Parse()
}

func main() {
	parsedPortsFlag := parsePorts()
	ports := make(chan uint64, numWorkers)
	results := make(chan uint64)
	var openPorts []uint64

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	go func() {
		for _, portNum := range parsedPortsFlag {
			ports <- portNum
		}
	}()

	for range parsedPortsFlag {
		port := <-results
		if port != 0 {
			openPorts = append(openPorts, port)
		}
	}

	close(ports)
	close(results)

	if len(openPorts) > 0 {
		fmt.Printf("[scandito]: Finished scanning %d ports on %s\n", len(parsedPortsFlag), host)
		sort.Slice(openPorts, func(i, j int) bool { return openPorts[i] < openPorts[j] })

		for _, port := range openPorts {
			fmt.Printf("[scandito]: port [%d] on host: [%s] is [OPEN]\n", port, host)
		}
	} else {
		fmt.Printf("[scandito]: Scanned %d ports, none were open for host %s.\n", len(parsedPortsFlag), host)
	}

}

// parsePorts checks different flag cases and generates []uint64
// containing ports to scan
func parsePorts() (parsedPorts []uint64) {
	ports = strings.ReplaceAll(ports, " ", "")
	switch {
	case strings.Contains(ports, "-"):
		portRange := []string{}

		if portRange = strings.Split(ports, "-"); len(portRange) > 2 {
			log.Fatalf("Invalid port range %s", ports)
		}

		startPort := parseAndValidatePort(portRange[0])
		endPort := parseAndValidatePort(portRange[1])

		if *startPort > *endPort {
			log.Fatal("Invalid range start port is greater than the end port")
		}

		for i := *startPort; i <= *endPort; i++ {
			parsedPorts = append(parsedPorts, i)
		}
	case strings.Contains(ports, ","):
		splitPorts := strings.Split(ports, ",")

		for _, port := range splitPorts {
			intPort := parseAndValidatePort(port)
			parsedPorts = append(parsedPorts, *intPort)
		}
	default:
		parsedPorts = append(parsedPorts, *parseAndValidatePort(ports))
	}

	return
}

// parseAndValidatePort converts string representation of port to uint64
// does basic tcp port validation
func parseAndValidatePort(port string) *uint64 {
	var err error
	var intPort uint64

	if intPort, err = strconv.ParseUint(port, 10, 32); err != nil {
		log.Fatalf("Error converting %s to uint port: %s", port, err)
	}

	if intPort == 0 || intPort > 65535 {
		log.Fatal("TCP port out of range, please only use ports 1 through 65535")
	}

	return &intPort
}

// worker generates a concurrent worker to scan ports
func worker(ports, results chan uint64) {
	for port := range ports {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.Dial("tcp", address)

		if err != nil {
			results <- 0
			continue
		}

		conn.Close()
		results <- port
	}
}
