package main

import (
	"context"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
	"time"
)

func NmapScanner(ListTargets []string, ListPorts []string) (NmapResult *nmap.Run, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), nmapTimeOutScan*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ListTargets...),
		nmap.WithPorts(ListPorts...),
		nmap.WithConnectScan(), //tcp connect only
		nmap.WithAggressiveScan(),
		nmap.WithServiceInfo(),
		nmap.WithVerbosity(3),
		nmap.WithScripts(nmapScriptName),
		nmap.WithScriptArguments(map[string]string{"mincvss": nmapScriptMinCvss}),
		nmap.WithContext(ctx),
	)
	if err != nil {
		logrus.Fatalf("Unable to create nmap scanner: %v", err)
	}

	logrus.Infof("Start Scanning hosts: %s ports %s", ListTargets, ListPorts)
	result, _, err := scanner.Run()
	if err != nil {
		logrus.Fatalf("Unable to run nmap scan: %v", err)
	}
	logrus.Infof("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	NmapResult = result
	return NmapResult, err
}
