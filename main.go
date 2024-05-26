package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

//go:embed dist/*
var staticFiles embed.FS

const DHCP_QUERY_FILTER = "udp and (port 67 or port 68)"

type DHCPRecord struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
}

var (
	dhcpRecord = make([]DHCPRecord, 0)
	mu         sync.Mutex
)

func parseDHCPOptions(options []layers.DHCPOption) (string, string, string) {
	var ipAddr, macAddr, hostname string
	for _, option := range options {
		switch option.Type {
		case layers.DHCPOptRequestIP:
			ipAddr = net.IP(option.Data).String()
		case layers.DHCPOptHostname:
			hostname = string(option.Data)
		}
	}
	return ipAddr, macAddr, hostname
}

func captureDHCPPackets(dhcpChan chan<- DHCPRecord, done <-chan struct{}) {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Panic(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(DHCP_QUERY_FILTER)
	if err != nil {
		log.Panic(err)
	}

	log.Println("capturing DHCP traffic...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-done:
			return
		case packet := <-packetSource.Packets():
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}

			eth, _ := ethLayer.(*layers.Ethernet)
			macAddr := eth.SrcMAC.String()
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				continue
			}

			dhcp, _ := dhcpLayer.(*layers.DHCPv4)
			if dhcp.Operation != layers.DHCPOpRequest {
				continue
			}

			ipAddr, _, hostname := parseDHCPOptions(dhcp.Options)
			log.Printf("Local IP: %s, MAC: %s, Hostname: %s\n", ipAddr, macAddr, hostname)
			record := DHCPRecord{
				ID:       strconv.FormatInt(time.Now().UTC().UnixNano(), 10),
				IP:       ipAddr,
				MAC:      macAddr,
				Hostname: hostname,
			}
			dhcpChan <- record
		}
	}
}

func main() {
	dhcpChan := make(chan DHCPRecord)
	done := make(chan struct{})

	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:5173"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
	}))

	// Create a filesystem from the embedded files but strip the "dist" prefix
	fs, err := fs.Sub(staticFiles, "dist")
	if err != nil {
		e.Logger.Fatal(err)
	}

	// e.Static("/", "dist")
	e.GET("/*", echo.WrapHandler(http.StripPrefix("/", http.FileServer(http.FS(fs)))))

	e.GET("/api/access-records", func(c echo.Context) error {
		mu.Lock()
		defer mu.Unlock()
		return c.JSON(http.StatusOK, dhcpRecord)
	})

	go func() {
		captureDHCPPackets(dhcpChan, done)
	}()

	go func() {
		for record := range dhcpChan {
			mu.Lock()
			dhcpRecord = append(dhcpRecord, record)
			mu.Unlock()
		}
	}()

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		close(done)
		close(dhcpChan)
		if err := e.Shutdown(context.TODO()); err != nil {
			log.Fatal(err)
		}
	}()

	if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
		log.Fatalf("shutting down server :%v", err)
	}

	log.Println("server shutdown gracefully")
}
