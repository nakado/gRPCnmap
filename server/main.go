package main

import (
	"fmt"
	pb "gRPCnmap/proto"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"strconv"
	"time"
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
		ll = logrus.DebugLevel
	}
	// set global log level
	logrus.SetLevel(ll)
}

const listnerAdress = ":5300"

const nmapScriptName = "vulners"
const nmapScriptMinCvss = "7.0"

func main() {
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
	response = NmapScanner(Targets, Ports)
	return response, nil
}

func Int32arrToStrArr(intArr []int32) []string {
	var strList []string
	for _, i := range intArr {
		strList = append(strList, strconv.FormatInt(int64(i), 10))
	}
	logrus.Debugf("format []int32->[]string correct")
	return strList
}

func NmapScanner(ListTargets []string, ListPorts []string) (NmapResponse *pb.CheckVulnResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ListTargets...),
		//nmap.WithPorts(ListPorts...),
		nmap.WithMostCommonPorts(20),
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
	logrus.Debugf("Start Packing to Response RPC")
	start := time.Now()

	TempResponse := &pb.CheckVulnResponse{}
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		for _, port := range host.Ports {

			for _, script := range port.Scripts {
				TempResult := pb.TargetResult{
					Target:   host.Addresses[0].Addr,
					Services: nil,
				}

				for _, listService := range script.Tables {
					NameService := port.Service.String()
					VersionService := listService.Key

					TempService := pb.Service{
						Name:    NameService,
						Version: VersionService,
						TcpPort: int32(port.ID),
						Vulns:   nil,
					}
					for _, listVulns := range listService.Tables {
						TempVulns := pb.Vulnerability{}
						for _, elementVulns := range listVulns.Elements {
							switch elementVulns.Key {
							case "cvss":
								temp := elementVulns.Value
								floatNum, err := strconv.ParseFloat(temp, 32)
								if err != nil {
									panic(err)
								}
								Score := float32(floatNum)
								TempVulns.CvssScore = Score
							case "id":
								identiferVuln := elementVulns.Value
								TempVulns.Identifier = identiferVuln
							}
						}
						TempService.Vulns = append(TempService.Vulns, &TempVulns)
					}
					if NameService != "" {
						TempResult.Services = append(TempResult.Services, &TempService)
					}
				}
				TempResponse.Results = append(TempResponse.Results, &TempResult)
			}
		}
		t := time.Now()
		elapsed := t.Sub(start)
		diff := fmt.Sprintf("duration: %s", elapsed)
		logrus.Debugf(diff)
	}
	return TempResponse
}
