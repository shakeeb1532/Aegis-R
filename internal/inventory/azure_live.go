package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (AzureAdapter) Load(cfg AdapterConfig) (Inventory, error) {
	if cfg.Azure.TenantID == "" || cfg.Azure.ClientID == "" || cfg.Azure.ClientSecret == "" {
		return Inventory{}, errors.New("azure adapter requires tenant_id, client_id, client_secret")
	}
	if cfg.Azure.Subscription == "" {
		return Inventory{}, errors.New("azure adapter requires subscription")
	}
	client := newAzureClient(cfg.Azure)

	users, err := client.listUsers()
	if err != nil {
		return Inventory{}, err
	}
	groups, userGroups, err := client.listGroupsWithMembers()
	if err != nil {
		return Inventory{}, err
	}
	roleDefs, err := client.listRoleDefinitions()
	if err != nil {
		return Inventory{}, err
	}
	roleAssignments, err := client.listRoleAssignments()
	if err != nil {
		return Inventory{}, err
	}
	vnets, subnets, err := client.listNetworks()
	if err != nil {
		return Inventory{}, err
	}
	peerings, err := client.listPeerings()
	if err != nil {
		return Inventory{}, err
	}
	routeTables, err := client.listRouteTables()
	if err != nil {
		return Inventory{}, err
	}
	nsgs, err := client.listNSGs()
	if err != nil {
		return Inventory{}, err
	}

	inv := Inventory{}
	for _, u := range users {
		inv.Azure.Users = append(inv.Azure.Users, AzureUser{
			ID:        u.ID,
			UPN:       u.UPN,
			PrivLevel: "standard",
			Groups:    userGroups[u.ID],
		})
	}
	for _, g := range groups {
		inv.Azure.Groups = append(inv.Azure.Groups, AzureGroup{ID: g.ID, Name: g.Name, Tags: []string{}, Users: userGroups["group:"+g.ID]})
	}
	for _, ra := range roleAssignments {
		roleName := roleDefs[ra.RoleDefinitionID]
		inv.Azure.RoleAssignments = append(inv.Azure.RoleAssignments, AzureRoleAssignment{
			Principal: ra.PrincipalID,
			Role:      firstNonEmpty(roleName, ra.RoleDefinitionID),
			Scope:     ra.Scope,
		})
	}
	inv.Azure.Networks = vnets
	inv.Azure.Subnets = subnets
	inv.Azure.NSGs = nsgs
	inv.Azure.Peerings = peerings
	inv.Azure.RouteTables = routeTables
	return inv, nil
}

type azureClient struct {
	tenantID string
	clientID string
	secret   string
	sub      string
	http     *http.Client
	graphTok string
	armTok   string
}

type azureUser struct {
	ID  string
	UPN string
}

type azureGroup struct {
	ID   string
	Name string
}

type azureRoleAssignment struct {
	PrincipalID      string
	RoleDefinitionID string
	Scope            string
}

func newAzureClient(cfg AzureConfig) *azureClient {
	return &azureClient{
		tenantID: cfg.TenantID,
		clientID: cfg.ClientID,
		secret:   cfg.ClientSecret,
		sub:      cfg.Subscription,
		http:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *azureClient) listUsers() ([]azureUser, error) {
	items := []azureUser{}
	path := "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail"
	return items, c.paginateGraph(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID  string `json:"id"`
				UPN string `json:"userPrincipalName"`
				Mail string `json:"mail"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Value {
			upn := firstNonEmpty(r.Mail, r.UPN, r.ID)
			items = append(items, azureUser{ID: r.ID, UPN: upn})
		}
		return nil
	})
}

func (c *azureClient) listGroupsWithMembers() ([]azureGroup, map[string][]string, error) {
	groups := []azureGroup{}
	userGroups := map[string][]string{}
	path := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName"
	if err := c.paginateGraph(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"displayName"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Value {
			groups = append(groups, azureGroup{ID: r.ID, Name: r.Name})
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	for _, g := range groups {
		members := []string{}
		path := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members?$select=id", g.ID)
		if err := c.paginateGraph(path, func(body []byte) error {
			var resp struct {
				Value []struct {
					ID string `json:"id"`
				} `json:"value"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return err
			}
			for _, r := range resp.Value {
				members = append(members, r.ID)
				userGroups[r.ID] = append(userGroups[r.ID], g.Name)
			}
			return nil
		}); err != nil {
			if isAzurePermissionErr(err) {
				continue
			}
			return nil, nil, err
		}
		userGroups["group:"+g.ID] = members
	}
	return groups, userGroups, nil
}

func isAzurePermissionErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "http 403") || strings.Contains(msg, "http 404")
}

func (c *azureClient) listRoleDefinitions() (map[string]string, error) {
	out := map[string]string{}
	path := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName"
	return out, c.paginateGraph(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"displayName"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Value {
			out[r.ID] = r.Name
		}
		return nil
	})
}

func (c *azureClient) listRoleAssignments() ([]azureRoleAssignment, error) {
	items := []azureRoleAssignment{}
	path := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=principalId,roleDefinitionId,directoryScopeId"
	return items, c.paginateGraph(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				PrincipalID      string `json:"principalId"`
				RoleDefinitionID string `json:"roleDefinitionId"`
				Scope            string `json:"directoryScopeId"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Value {
			items = append(items, azureRoleAssignment{PrincipalID: r.PrincipalID, RoleDefinitionID: r.RoleDefinitionID, Scope: r.Scope})
		}
		return nil
	})
}

func (c *azureClient) listNetworks() ([]AzureNetwork, []AzureSubnet, error) {
	vnets := []AzureNetwork{}
	subnets := []AzureSubnet{}
	path := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/virtualNetworks?api-version=2023-05-01", c.sub)
	return vnets, subnets, c.paginateARM(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Location string `json:"location"`
				Props    struct {
					Subnets []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"subnets"`
				} `json:"properties"`
			} `json:"value"`
			Next string `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, v := range resp.Value {
			vnets = append(vnets, AzureNetwork{ID: v.ID, Name: v.Name, Tags: []string{}})
			for _, s := range v.Props.Subnets {
				subnets = append(subnets, AzureSubnet{ID: s.ID, Network: v.ID, Zone: v.Location, Tags: []string{}})
			}
		}
		return nil
	})
}

func (c *azureClient) listPeerings() ([]AzurePeering, error) {
	peerings := []AzurePeering{}
	path := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/virtualNetworks?api-version=2023-05-01", c.sub)
	return peerings, c.paginateARM(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Props struct {
					Peerings []struct {
						ID    string `json:"id"`
						Name  string `json:"name"`
						Props struct {
							Remote struct {
								ID string `json:"id"`
							} `json:"remoteVirtualNetwork"`
							State string `json:"peeringState"`
						} `json:"properties"`
					} `json:"virtualNetworkPeerings"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, v := range resp.Value {
			for _, p := range v.Props.Peerings {
				peerings = append(peerings, AzurePeering{
					ID:       p.ID,
					FromVNet: v.ID,
					ToVNet:   p.Props.Remote.ID,
					Mode:     p.Props.State,
				})
			}
		}
		return nil
	})
}

func (c *azureClient) listRouteTables() ([]AzureRouteTable, error) {
	tables := []AzureRouteTable{}
	path := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/routeTables?api-version=2023-05-01", c.sub)
	return tables, c.paginateARM(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Props struct {
					Routes []struct {
						Name  string `json:"name"`
						Props struct {
							AddressPrefix string `json:"addressPrefix"`
							NextHopType   string `json:"nextHopType"`
						} `json:"properties"`
					} `json:"routes"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Value {
			routes := []AzureRoute{}
			for _, route := range r.Props.Routes {
				routes = append(routes, AzureRoute{
					AddressPrefix: route.Props.AddressPrefix,
					NextHopType:   route.Props.NextHopType,
					Notes:         route.Name,
				})
			}
			tables = append(tables, AzureRouteTable{
				ID:     r.ID,
				Routes: routes,
			})
		}
		return nil
	})
}

func (c *azureClient) listNSGs() ([]AzureNSG, error) {
	nsgs := []AzureNSG{}
	path := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01", c.sub)
	return nsgs, c.paginateARM(path, func(body []byte) error {
		var resp struct {
			Value []struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Props struct {
					Rules []struct {
						Name  string `json:"name"`
						Props struct {
							Access                 string   `json:"access"`
							Protocol               string   `json:"protocol"`
							SourceAddressPrefix    string   `json:"sourceAddressPrefix"`
							SourceAddressPrefixes  []string `json:"sourceAddressPrefixes"`
							DestinationAddressPrefix   string   `json:"destinationAddressPrefix"`
							DestinationAddressPrefixes []string `json:"destinationAddressPrefixes"`
							DestinationPortRange   string   `json:"destinationPortRange"`
							DestinationPortRanges  []string `json:"destinationPortRanges"`
						} `json:"properties"`
					} `json:"securityRules"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		for _, r := range resp.Value {
			rules := []AzureRule{}
			for _, rule := range r.Props.Rules {
				srcs := append(rule.Props.SourceAddressPrefixes, rule.Props.SourceAddressPrefix)
				dsts := append(rule.Props.DestinationAddressPrefixes, rule.Props.DestinationAddressPrefix)
				ports := append(rule.Props.DestinationPortRanges, rule.Props.DestinationPortRange)
				src := firstNonEmpty(srcs...)
				dst := firstNonEmpty(dsts...)
				port := firstNonEmpty(ports...)
				rules = append(rules, AzureRule{Source: src, Destination: dst, Protocol: rule.Props.Protocol, Port: port, Action: rule.Props.Access, Notes: rule.Name})
			}
			nsgs = append(nsgs, AzureNSG{ID: r.ID, Name: r.Name, Network: "", Rules: rules})
		}
		return nil
	})
}

func (c *azureClient) paginateGraph(path string, handle func([]byte) error) error {
	tok, err := c.token("https://graph.microsoft.com/.default")
	if err != nil {
		return err
	}
	next := path
	for next != "" {
		body, nextLink, err := c.getWithNext(tok, next)
		if err != nil {
			return err
		}
		if err := handle(body); err != nil {
			return err
		}
		next = nextLink
	}
	return nil
}

func (c *azureClient) paginateARM(path string, handle func([]byte) error) error {
	tok, err := c.token("https://management.azure.com/.default")
	if err != nil {
		return err
	}
	next := path
	for next != "" {
		body, nextLink, err := c.getWithNext(tok, next)
		if err != nil {
			return err
		}
		if err := handle(body); err != nil {
			return err
		}
		next = nextLink
	}
	return nil
}

func (c *azureClient) getWithNext(token string, urlStr string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("azure http %d", resp.StatusCode)
	}
	var probe struct {
		Next string `json:"@odata.nextLink"`
		Alt  string `json:"nextLink"`
	}
	_ = json.Unmarshal(body, &probe)
	next := firstNonEmpty(probe.Next, probe.Alt)
	return body, next, nil
}

func (c *azureClient) token(scope string) (string, error) {
	if scope == "https://graph.microsoft.com/.default" && c.graphTok != "" {
		return c.graphTok, nil
	}
	if scope == "https://management.azure.com/.default" && c.armTok != "" {
		return c.armTok, nil
	}
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.secret)
	form.Set("scope", scope)
	form.Set("grant_type", "client_credentials")
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID)
	resp, err := c.http.PostForm(endpoint, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token http %d", resp.StatusCode)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if scope == "https://graph.microsoft.com/.default" {
		c.graphTok = parsed.AccessToken
	}
	if scope == "https://management.azure.com/.default" {
		c.armTok = parsed.AccessToken
	}
	return parsed.AccessToken, nil
}
