package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func (GCPAdapter) Load(cfg AdapterConfig) (Inventory, error) {
	if cfg.GCP.ProjectID == "" {
		return Inventory{}, errors.New("gcp adapter requires project_id")
	}
	ctx := context.Background()
	creds, err := gcpCredentials(ctx, cfg)
	if err != nil {
		return Inventory{}, err
	}
	crmSvc, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return Inventory{}, err
	}
	computeSvc, err := compute.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return Inventory{}, err
	}
	iamSvc, err := iam.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return Inventory{}, err
	}

	inv := Inventory{}
	if err := loadGCPProjects(ctx, crmSvc, &inv, cfg.GCP.ProjectID); err != nil {
		return Inventory{}, err
	}
	if err := loadGCPIAM(ctx, crmSvc, &inv, cfg.GCP.ProjectID); err != nil {
		return Inventory{}, err
	}
	if err := loadGCPServiceAccounts(ctx, iamSvc, &inv, cfg.GCP.ProjectID); err != nil {
		return Inventory{}, err
	}
	if err := loadGCPNetworks(ctx, computeSvc, &inv, cfg.GCP.ProjectID); err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

func gcpCredentials(ctx context.Context, cfg AdapterConfig) (*google.Credentials, error) {
	if cfg.GCP.CredsJSON != "" {
		return google.CredentialsFromJSON(ctx, []byte(cfg.GCP.CredsJSON), compute.CloudPlatformScope, cloudresourcemanager.CloudPlatformScope, iam.CloudPlatformScope)
	}
	if cfg.GCP.CredsFile != "" {
		data, err := os.ReadFile(cfg.GCP.CredsFile)
		if err != nil {
			return nil, err
		}
		return google.CredentialsFromJSON(ctx, data, compute.CloudPlatformScope, cloudresourcemanager.CloudPlatformScope, iam.CloudPlatformScope)
	}
	return google.FindDefaultCredentials(ctx, compute.CloudPlatformScope, cloudresourcemanager.CloudPlatformScope, iam.CloudPlatformScope)
}

func loadGCPProjects(ctx context.Context, svc *cloudresourcemanager.Service, inv *Inventory, projectID string) error {
	proj, err := svc.Projects.Get(projectID).Do()
	if err != nil {
		return err
	}
	inv.GCP.Projects = append(inv.GCP.Projects, GCPProject{ID: proj.ProjectId, Name: proj.Name, Tags: []string{}})
	return nil
}

func loadGCPIAM(ctx context.Context, svc *cloudresourcemanager.Service, inv *Inventory, projectID string) error {
	policy, err := svc.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return err
	}
	for _, b := range policy.Bindings {
		role := b.Role
		for _, m := range b.Members {
			member := m
			inv.GCP.IAMBindings = append(inv.GCP.IAMBindings, GCPIAMBinding{Member: member, Role: role, Scope: "project:" + projectID})
			if strings.HasPrefix(member, "user:") {
				inv.GCP.Users = append(inv.GCP.Users, GCPUser{ID: member, Email: strings.TrimPrefix(member, "user:"), PrivLevel: "standard", Groups: []string{}})
			}
		}
	}
	return nil
}

func loadGCPServiceAccounts(ctx context.Context, svc *iam.Service, inv *Inventory, projectID string) error {
	name := fmt.Sprintf("projects/%s", projectID)
	resp, err := svc.Projects.ServiceAccounts.List(name).Do()
	if err != nil {
		return err
	}
	for _, sa := range resp.Accounts {
		inv.GCP.ServiceAccounts = append(inv.GCP.ServiceAccounts, GCPServiceAcct{ID: sa.Name, Email: sa.Email, PrivLevel: "unknown", Tags: []string{}})
	}
	return nil
}

func loadGCPNetworks(ctx context.Context, svc *compute.Service, inv *Inventory, projectID string) error {
	networks, err := svc.Networks.List(projectID).Do()
	if err != nil {
		return err
	}
	for _, n := range networks.Items {
		inv.GCP.Networks = append(inv.GCP.Networks, GCPNetwork{ID: n.SelfLink, Name: n.Name, Tags: []string{}})
	}

	subnets, err := svc.Subnetworks.AggregatedList(projectID).Do()
	if err != nil {
		return err
	}
	for _, sc := range subnets.Items {
		for _, s := range sc.Subnetworks {
			inv.GCP.Subnets = append(inv.GCP.Subnets, GCPSubnet{ID: s.SelfLink, Network: s.Network, Zone: s.Region, Tags: []string{}})
		}
	}

	firewalls, err := svc.Firewalls.List(projectID).Do()
	if err != nil {
		return err
	}
	for _, f := range firewalls.Items {
		action := "allow"
		if f.Denied != nil && len(f.Denied) > 0 {
			action = "deny"
		}
		sources := append([]string{}, f.SourceRanges...)
		dests := ""
		if len(f.TargetTags) > 0 {
			dests = strings.Join(f.TargetTags, ",")
		}
		port := ""
		proto := ""
		if len(f.Allowed) > 0 {
			proto = f.Allowed[0].IPProtocol
			if len(f.Allowed[0].Ports) > 0 {
				port = f.Allowed[0].Ports[0]
			}
		}
		src := firstNonEmpty(sources...)
		inv.GCP.FirewallRules = append(inv.GCP.FirewallRules, GCPFirewallRule{
			ID:          f.SelfLink,
			Network:     f.Network,
			Direction:   f.Direction,
			Source:      src,
			Destination: dests,
			Protocol:    proto,
			Port:        port,
			Action:      action,
			Notes:       f.Name,
		})
	}
	return nil
}
