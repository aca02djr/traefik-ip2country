package traefik_ip2country

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"sort"
)

type entry struct {
	from    uint32
	to      uint32
	country string
}

func countryForIP(ipString string) string {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return ""
	}
	ipUint := binary.BigEndian.Uint32(ip[12:16])
	index := sort.Search(len(entries), func(i int) bool { return ipUint <= entries[i].to })
	if index < len(entries) && ipUint >= entries[index].from {
		return entries[index].country
	}
	return ""
}

// Config the plugin configuration.
type Config struct {
	Whitelist []string `json:"whitelist" yaml:"whitelist" toml:"whitelist"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Whitelist: []string{},
	}
}

// IP2Country plugin to whitelist requests by country.
type IP2Country struct {
	whitelist map[string]bool
	next      http.Handler
}

// New creates a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	whitelist := map[string]bool{}
	for _, country := range config.Whitelist {
		whitelist[country] = true
	}
	return &IP2Country{whitelist: whitelist, next: next}, nil
}

func (e *IP2Country) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ipAddress, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Printf("ip2country: unable to determine IP address\n")
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	country := countryForIP(ipAddress)
	if country == "" {
		log.Printf("ip2country: unable to determine country for IP address %s\n", ipAddress)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	_, isAllowed := e.whitelist[country]
	if isAllowed {
		e.next.ServeHTTP(rw, req)
		return
	}
	log.Printf("ip2country: request blocked from IP address %s (country %s)\n", ipAddress, country)
	rw.WriteHeader(http.StatusForbidden)
}
