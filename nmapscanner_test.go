package main

import (
	"github.com/sirupsen/logrus"
	"testing"
)

func TestNmapScanner(t *testing.T) {
	logrus.SetLevel(logLevel)
	target := []string{"scanme.nmap.org"}
	ports := []string{"80"}
	result, err := NmapScanner(target, ports)
	if err != nil {
		t.Errorf("something goes wrong %s", err)
	}
	hostsUp := result.Stats.Hosts.Up
	if hostsUp != 1 {
		t.Errorf("No connection with %s", target)
	}

}
