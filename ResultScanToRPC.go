package main

import (
	pb "gRPCnmap/proto"
	"github.com/Ullaakut/nmap/v2"
	"github.com/sirupsen/logrus"
	"strconv"
)

func ResultScanToRPC(result *nmap.Run) (TempResponse *pb.CheckVulnResponse) {
	TempResponse = &pb.CheckVulnResponse{}
	logrus.Debugf("Start Packing to Response RPC")
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

	}
	logrus.Debugf("Packing is finished")
	return TempResponse
}
