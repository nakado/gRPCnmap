package main

import (
	pb "gRPCnmap/proto"
	"github.com/sirupsen/logrus"
	"reflect"
	"testing"
)

func TestResultScanToRPC(t *testing.T) {
	logrus.SetLevel(logLevel)
	target := []string{"192.168.0.1"}
	ports := []string{"0"}
	result, err := NmapScanner(target, ports)
	if err != nil {
		t.Errorf("something goes wrong: %s", err)
	}
	emptyResponce := &pb.CheckVulnResponse{Results: []*pb.TargetResult{{
		Target: "192.168.0.1",
		Services: []*pb.Service{{
			Name:    "http",
			Version: "",
			TcpPort: 80,
			Vulns:   nil,
		}},
	}}}
	// TODO: develop a variation of the test
	rpcResType := reflect.TypeOf(ResultScanToRPC(result))
	emptResType := reflect.TypeOf(emptyResponce)
	if rpcResType != emptResType {
		t.Errorf("something with Packing:")
	}
}
