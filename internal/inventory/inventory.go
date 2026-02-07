package inventory

import (
	"sort"
	"strings"

	"aegisr/internal/env"
)

type Inventory struct {
	AWS   AWSInventory
	Okta  OktaInventory
	Azure AzureInventory
	GCP   GCPInventory
}

type AWSInventory struct {
	Accounts       []AWSAccount       `json:"accounts"`
	Users          []AWSUser          `json:"users"`
	Roles          []AWSRole          `json:"roles"`
	Instances      []AWSInstance      `json:"instances"`
	SecurityGroups []AWSSecurityGroup `json:"security_groups"`
	VPCs           []AWSVPC           `json:"vpcs"`
	Subnets        []AWSSubnet        `json:"subnets"`
}

type AWSAccount struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type AWSUser struct {
	ID        string   `json:"id"`
	UserName  string   `json:"username"`
	PrivLevel string   `json:"priv_level"`
	Tags      []string `json:"tags"`
}

type AWSRole struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	PrivLevel string   `json:"priv_level"`
	Trusts    []string `json:"trusts"`
	Tags      []string `json:"tags"`
}

type AWSInstance struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	VPC      string   `json:"vpc"`
	Subnet   string   `json:"subnet"`
	Zone     string   `json:"zone"`
	Critical bool     `json:"critical"`
	Tags     []string `json:"tags"`
}

type AWSVPC struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type AWSSubnet struct {
	ID   string   `json:"id"`
	VPC  string   `json:"vpc"`
	Zone string   `json:"zone"`
	Tags []string `json:"tags"`
}

type AWSSecurityGroup struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	VPC     string        `json:"vpc"`
	Ingress []AWSRule     `json:"ingress"`
	Egress  []AWSRule     `json:"egress"`
	Tags    []string      `json:"tags"`
}

type AWSRule struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        string `json:"port"`
	Notes       string `json:"notes"`
}

type OktaInventory struct {
	Users  []OktaUser  `json:"users"`
	Groups []OktaGroup `json:"groups"`
	Roles  []OktaRole  `json:"roles"`
	Apps   []OktaApp   `json:"apps"`
}

type OktaUser struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Role      string   `json:"role"`
	PrivLevel string   `json:"priv_level"`
	Groups    []string `json:"groups"`
	Status    string   `json:"status"`
}

type OktaGroup struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Tags  []string `json:"tags"`
	Users []string `json:"users"`
}

type OktaRole struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Users []string `json:"users"`
}

type OktaApp struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Users []string `json:"users"`
	Tags  []string `json:"tags"`
}

type AzureInventory struct {
	Users           []AzureUser           `json:"users"`
	Groups          []AzureGroup          `json:"groups"`
	RoleAssignments []AzureRoleAssignment `json:"role_assignments"`
	Networks        []AzureNetwork        `json:"networks"`
	Subnets         []AzureSubnet         `json:"subnets"`
	NSGs            []AzureNSG            `json:"nsgs"`
}

type AzureUser struct {
	ID        string   `json:"id"`
	UPN       string   `json:"upn"`
	PrivLevel string   `json:"priv_level"`
	Groups    []string `json:"groups"`
}

type AzureGroup struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Tags  []string `json:"tags"`
	Users []string `json:"users"`
}

type AzureRoleAssignment struct {
	Principal string `json:"principal"`
	Role      string `json:"role"`
	Scope     string `json:"scope"`
}

type AzureNetwork struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type AzureSubnet struct {
	ID      string   `json:"id"`
	Network string   `json:"network"`
	Zone    string   `json:"zone"`
	Tags    []string `json:"tags"`
}

type AzureNSG struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Network string       `json:"network"`
	Rules   []AzureRule  `json:"rules"`
}

type AzureRule struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        string `json:"port"`
	Action      string `json:"action"`
	Notes       string `json:"notes"`
}

type GCPInventory struct {
	Projects       []GCPProject      `json:"projects"`
	Users          []GCPUser         `json:"users"`
	ServiceAccounts []GCPServiceAcct `json:"service_accounts"`
	IAMBindings    []GCPIAMBinding   `json:"iam_bindings"`
	Networks       []GCPNetwork      `json:"networks"`
	Subnets        []GCPSubnet       `json:"subnets"`
	FirewallRules  []GCPFirewallRule `json:"firewall_rules"`
}

type GCPProject struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type GCPUser struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	PrivLevel string   `json:"priv_level"`
	Groups    []string `json:"groups"`
}

type GCPServiceAcct struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	PrivLevel string   `json:"priv_level"`
	Tags      []string `json:"tags"`
}

type GCPIAMBinding struct {
	Member string `json:"member"`
	Role   string `json:"role"`
	Scope  string `json:"scope"`
}

type GCPNetwork struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type GCPSubnet struct {
	ID      string   `json:"id"`
	Network string   `json:"network"`
	Zone    string   `json:"zone"`
	Tags    []string `json:"tags"`
}

type GCPFirewallRule struct {
	ID          string   `json:"id"`
	Network     string   `json:"network"`
	Direction   string   `json:"direction"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Protocol    string   `json:"protocol"`
	Port        string   `json:"port"`
	Action      string   `json:"action"`
	Notes       string   `json:"notes"`
}

func BuildEnvironment(inv Inventory) env.Environment {
	hosts := map[string]env.Host{}
	idents := map[string]env.Identity{}
	trusts := map[string]env.TrustBoundary{}

	addHost := func(h env.Host) {
		if h.ID == "" {
			return
		}
		hosts[h.ID] = h
	}
	addIdent := func(i env.Identity) {
		if i.ID == "" {
			return
		}
		idents[i.ID] = i
	}
	addTrust := func(t env.TrustBoundary) {
		if t.ID == "" {
			return
		}
		trusts[t.ID] = t
	}

	for _, inst := range inv.AWS.Instances {
		zone := firstNonEmpty(inst.Zone, inst.Subnet, inst.VPC, "aws")
		addHost(env.Host{ID: inst.ID, Zone: zone, Tags: append([]string{"aws"}, inst.Tags...), Critical: inst.Critical})
	}
	for _, u := range inv.AWS.Users {
		role := firstNonEmpty(u.UserName, u.ID)
		addIdent(env.Identity{ID: u.ID, Role: role, PrivLevel: u.PrivLevel, Tags: append([]string{"aws", "iam:user"}, u.Tags...)})
	}
	for _, r := range inv.AWS.Roles {
		addIdent(env.Identity{ID: r.ID, Role: r.Name, PrivLevel: r.PrivLevel, Tags: append([]string{"aws", "iam:role"}, r.Tags...)})
		for _, principal := range r.Trusts {
			id := strings.Join([]string{"aws", "trust", principal, r.ID}, ":")
			addTrust(env.TrustBoundary{ID: id, From: principal, To: r.ID, Mode: "allow", Notes: "role trust"})
		}
	}
	for _, sg := range inv.AWS.SecurityGroups {
		for _, rule := range sg.Ingress {
			id := strings.Join([]string{"aws", "sg", sg.ID, "ingress", rule.Source, rule.Port}, ":")
			addTrust(env.TrustBoundary{ID: id, From: rule.Source, To: sg.ID, Mode: "allow", Notes: rule.Notes})
		}
		for _, rule := range sg.Egress {
			id := strings.Join([]string{"aws", "sg", sg.ID, "egress", rule.Destination, rule.Port}, ":")
			addTrust(env.TrustBoundary{ID: id, From: sg.ID, To: rule.Destination, Mode: "allow", Notes: rule.Notes})
		}
	}

	for _, u := range inv.Okta.Users {
		role := firstNonEmpty(u.Role, u.Email, u.ID)
		tags := append([]string{"okta"}, u.Groups...)
		if u.Status != "" {
			tags = append(tags, "status:"+u.Status)
		}
		addIdent(env.Identity{ID: u.ID, Role: role, PrivLevel: u.PrivLevel, Tags: tags})
	}

	for _, u := range inv.Azure.Users {
		role := firstNonEmpty(u.UPN, u.ID)
		addIdent(env.Identity{ID: u.ID, Role: role, PrivLevel: u.PrivLevel, Tags: append([]string{"azure"}, u.Groups...)})
	}
	for _, ra := range inv.Azure.RoleAssignments {
		id := strings.Join([]string{"azure", "role", ra.Principal, ra.Role}, ":")
		addTrust(env.TrustBoundary{ID: id, From: ra.Principal, To: ra.Scope, Mode: "allow", Notes: ra.Role})
	}
	for _, nsg := range inv.Azure.NSGs {
		for _, rule := range nsg.Rules {
			mode := strings.ToLower(rule.Action)
			if mode == "" {
				mode = "allow"
			}
			id := strings.Join([]string{"azure", "nsg", nsg.ID, rule.Source, rule.Destination, rule.Port}, ":")
			addTrust(env.TrustBoundary{ID: id, From: rule.Source, To: rule.Destination, Mode: mode, Notes: rule.Notes})
		}
	}

	for _, u := range inv.GCP.Users {
		role := firstNonEmpty(u.Email, u.ID)
		addIdent(env.Identity{ID: u.ID, Role: role, PrivLevel: u.PrivLevel, Tags: append([]string{"gcp"}, u.Groups...)})
	}
	for _, sa := range inv.GCP.ServiceAccounts {
		role := firstNonEmpty(sa.Email, sa.ID)
		addIdent(env.Identity{ID: sa.ID, Role: role, PrivLevel: sa.PrivLevel, Tags: append([]string{"gcp", "service-account"}, sa.Tags...)})
	}
	for _, b := range inv.GCP.IAMBindings {
		id := strings.Join([]string{"gcp", "binding", b.Member, b.Role}, ":")
		addTrust(env.TrustBoundary{ID: id, From: b.Member, To: b.Scope, Mode: "allow", Notes: b.Role})
	}
	for _, r := range inv.GCP.FirewallRules {
		mode := strings.ToLower(r.Action)
		if mode == "" {
			mode = "allow"
		}
		id := strings.Join([]string{"gcp", "fw", r.ID, r.Source, r.Destination, r.Port}, ":")
		addTrust(env.TrustBoundary{ID: id, From: r.Source, To: r.Destination, Mode: mode, Notes: r.Notes})
	}

	envOut := env.Environment{
		Hosts:           mapHosts(hosts),
		Identities:      mapIdentities(idents),
		TrustBoundaries: mapTrusts(trusts),
	}
	return envOut
}

func mapHosts(in map[string]env.Host) []env.Host {
	out := make([]env.Host, 0, len(in))
	for _, h := range in {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mapIdentities(in map[string]env.Identity) []env.Identity {
	out := make([]env.Identity, 0, len(in))
	for _, h := range in {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mapTrusts(in map[string]env.TrustBoundary) []env.TrustBoundary {
	out := make([]env.TrustBoundary, 0, len(in))
	for _, h := range in {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
