package main

import (
	pb "gRPCnmap/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
)

func init() {
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, let's default to debug
	if !ok {
		lvl = "debug"
	}
	// parse string, this is built-in feature of logrus
	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logLevel
	}
	// set global log level
	logrus.SetLevel(ll)
}

const listnerAdress = ":5300"

var logLevel = logrus.DebugLevel

const nmapScriptName = "vulners"
const nmapScriptMinCvss = "7.0"
const nmapTimeOutScan = 300 // seconds

func main() {
	logrus.SetLevel(logLevel) // todo: check about work logrus output
	listener, err := net.Listen("tcp", listnerAdress)
	logrus.Infof("Start TCP listner at %s", listnerAdress)
	if err != nil {
		logrus.Errorf("Failed to listen: %v", err)
	}

	opts := []grpc.ServerOption{}
	grpcServer := grpc.NewServer(opts...)

	pb.RegisterNetVulnServiceServer(grpcServer, &server{})
	grpcServer.Serve(listener)
}

type server struct {
	pb.UnimplementedNetVulnServiceServer
}

func (s *server) CheckVuln(c context.Context, request *pb.CheckVulnRequest) (response *pb.CheckVulnResponse, err error) {
	Targets := request.Targets
	Ports := Int32arrToStrArr(request.TcpPorts)
	result, err := NmapScanner(Targets, Ports)
	response = ResultScanToRPC(result)
	return response, err
}
