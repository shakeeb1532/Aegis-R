package inventory

import "testing"

func TestBuildEnvironmentTopology(t *testing.T) {
	inv := Inventory{
		AWS: AWSInventory{
			RouteTables: []AWSRouteTable{{ID: "rtb-1", VPC: "vpc-1", Routes: []AWSRoute{{Destination: "0.0.0.0/0", Target: "igw-1", TargetType: "gateway"}}}},
			Peerings:    []AWSPeering{{ID: "pcx-1", FromVPC: "vpc-1", ToVPC: "vpc-2", Status: "active"}},
		},
		Azure: AzureInventory{
			RouteTables: []AzureRouteTable{{ID: "rt-1", Network: "vnet-1", Routes: []AzureRoute{{AddressPrefix: "0.0.0.0/0", NextHopType: "Internet"}}}},
			Peerings:    []AzurePeering{{ID: "peer-1", FromVNet: "vnet-1", ToVNet: "vnet-2", Mode: "Connected"}},
		},
		GCP: GCPInventory{
			Routes:   []GCPRoute{{ID: "r-1", Network: "net-1", DestinationRange: "0.0.0.0/0", NextHopType: "internet"}},
			Peerings: []GCPPeering{{ID: "peer-1", Network: "net-1", Peer: "net-2", State: "ACTIVE"}},
		},
	}
	env := BuildEnvironment(inv)
	if len(env.TrustBoundaries) == 0 {
		t.Fatalf("expected trust boundaries")
	}
	// Expect at least one internet egress trust boundary.
	foundInternet := false
	for _, t := range env.TrustBoundaries {
		if t.To == "internet" {
			foundInternet = true
			break
		}
	}
	if !foundInternet {
		t.Fatalf("expected internet egress trust boundary")
	}
}
