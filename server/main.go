package main

import (
	"fmt"
	pb "gRPCnmap/proto"
	"github.com/Ullaakut/nmap/v2"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"log"
	"net"
	"strconv"
	"time"
)

const nmapScriptName = "vulners"
const nmapScriptMinCvss = "7.0"

func main() {
	listener, err := net.Listen("tcp", ":5300")
	log.Println("start listnening")

	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
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
	checkTarget := request.Targets
	check_port := request.TcpPorts
	var ListPorts []string
	for _, i := range check_port {
		ListPorts = append(ListPorts, strconv.FormatInt(int64(i), 10))
	}

	fmt.Printf("targets is :%s\n %s", checkTarget, ListPorts)
	response = NmapScanner(checkTarget, ListPorts)
	return response, nil
}

func NmapScanner(ListTargets []string, ListPorts []string) (NmapResponse *pb.CheckVulnResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	log.Println("now")

	TempResponse := &pb.CheckVulnResponse{}
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

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
		fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	}
	return TempResponse
}
