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

func (OktaAdapter) Load(cfg AdapterConfig) (Inventory, error) {
	if cfg.Okta.OrgURL == "" || cfg.Okta.Token == "" {
		return Inventory{}, errors.New("okta adapter requires org_url and token")
	}
	client, err := newOktaClient(cfg.Okta.OrgURL, cfg.Okta.Token)
	if err != nil {
		return Inventory{}, err
	}

	users, err := client.listUsers()
	if err != nil {
		return Inventory{}, err
	}
	groups, groupMembers, err := client.listGroupsWithMembers()
	if err != nil {
		return Inventory{}, err
	}
	apps, appUsers, err := client.listAppsWithUsers()
	if err != nil {
		return Inventory{}, err
	}
	roles, userRoles, err := client.listUserRoles(users)
	if err != nil {
		return Inventory{}, err
	}

	inv := Inventory{}
	for _, u := range users {
		roleName := ""
		if rolesForUser := userRoles[u.ID]; len(rolesForUser) > 0 {
			roleName = rolesForUser[0].Name
		}
		priv := "standard"
		if strings.Contains(strings.ToLower(roleName), "admin") {
			priv = "admin"
		}
		inv.Okta.Users = append(inv.Okta.Users, OktaUser{
			ID:        u.ID,
			Email:     u.Email,
			Role:      roleName,
			PrivLevel: priv,
			Groups:    groupMembers[u.ID],
			Status:    u.Status,
		})
	}
	for _, g := range groups {
		inv.Okta.Groups = append(inv.Okta.Groups, OktaGroup{
			ID:    g.ID,
			Name:  g.Name,
			Tags:  []string{},
			Users: groupMembers["group:"+g.ID],
		})
	}
	for _, r := range roles {
		inv.Okta.Roles = append(inv.Okta.Roles, OktaRole{ID: r.ID, Name: r.Name, Users: r.Users})
	}
	for _, a := range apps {
		inv.Okta.Apps = append(inv.Okta.Apps, OktaApp{ID: a.ID, Name: a.Name, Users: appUsers[a.ID], Tags: []string{}})
	}
	return inv, nil
}

type oktaClient struct {
	base *url.URL
	http *http.Client
	token string
}

type oktaUser struct {
	ID     string
	Email  string
	Status string
}

type oktaGroup struct {
	ID   string
	Name string
}

type oktaRole struct {
	ID    string
	Name  string
	Users []string
}

type oktaApp struct {
	ID   string
	Name string
}

func newOktaClient(orgURL string, token string) (*oktaClient, error) {
	base, err := url.Parse(strings.TrimRight(orgURL, "/"))
	if err != nil {
		return nil, err
	}
	return &oktaClient{
		base:  base,
		token: token,
		http: &http.Client{Timeout: 20 * time.Second},
	}, nil
}

func (c *oktaClient) listUsers() ([]oktaUser, error) {
	items := []oktaUser{}
	err := c.paginate("/api/v1/users?limit=200", func(body []byte) error {
		var rows []struct {
			ID      string `json:"id"`
			Status  string `json:"status"`
			Profile struct {
				Login string `json:"login"`
				Email string `json:"email"`
			} `json:"profile"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			email := firstNonEmpty(r.Profile.Email, r.Profile.Login)
			items = append(items, oktaUser{ID: r.ID, Email: email, Status: r.Status})
		}
		return nil
	})
	return items, err
}

func (c *oktaClient) listGroupsWithMembers() ([]oktaGroup, map[string][]string, error) {
	groups := []oktaGroup{}
	groupMembers := map[string][]string{}
	userGroups := map[string][]string{}
	err := c.paginate("/api/v1/groups?limit=200", func(body []byte) error {
		var rows []struct {
			ID      string `json:"id"`
			Profile struct {
				Name string `json:"name"`
			} `json:"profile"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			groups = append(groups, oktaGroup{ID: r.ID, Name: r.Profile.Name})
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for _, g := range groups {
		members := []string{}
		path := fmt.Sprintf("/api/v1/groups/%s/users?limit=200", g.ID)
		if err := c.paginate(path, func(body []byte) error {
			var rows []struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(body, &rows); err != nil {
				return err
			}
			for _, r := range rows {
				members = append(members, r.ID)
				userGroups[r.ID] = append(userGroups[r.ID], g.Name)
			}
			return nil
		}); err != nil {
			return nil, nil, err
		}
		groupMembers["group:"+g.ID] = members
	}
	for uid, gs := range userGroups {
		groupMembers[uid] = gs
	}
	return groups, groupMembers, nil
}

func (c *oktaClient) listAppsWithUsers() ([]oktaApp, map[string][]string, error) {
	apps := []oktaApp{}
	appUsers := map[string][]string{}
	if err := c.paginate("/api/v1/apps?limit=200", func(body []byte) error {
		var rows []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			apps = append(apps, oktaApp{ID: r.ID, Name: r.Label})
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	for _, a := range apps {
		users := []string{}
		path := fmt.Sprintf("/api/v1/apps/%s/users?limit=200", a.ID)
		if err := c.paginate(path, func(body []byte) error {
			var rows []struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(body, &rows); err != nil {
				return err
			}
			for _, r := range rows {
				users = append(users, r.ID)
			}
			return nil
		}); err != nil {
			if isPermissionErr(err) {
				continue
			}
			return nil, nil, err
		}
		appUsers[a.ID] = users
	}
	return apps, appUsers, nil
}

func (c *oktaClient) listUserRoles(users []oktaUser) ([]oktaRole, map[string][]oktaRole, error) {
	roles := []oktaRole{}
	userRoles := map[string][]oktaRole{}
	for _, u := range users {
		path := fmt.Sprintf("/api/v1/users/%s/roles", u.ID)
		if err := c.paginate(path, func(body []byte) error {
			var rows []struct {
				ID    string `json:"id"`
				Label string `json:"label"`
				Type  string `json:"type"`
			}
			if err := json.Unmarshal(body, &rows); err != nil {
				return err
			}
			for _, r := range rows {
				role := oktaRole{ID: r.ID, Name: firstNonEmpty(r.Label, r.Type), Users: []string{u.ID}}
				roles = append(roles, role)
				userRoles[u.ID] = append(userRoles[u.ID], role)
			}
			return nil
		}); err != nil {
			if isPermissionErr(err) {
				continue
			}
			return nil, nil, err
		}
	}
	return roles, userRoles, nil
}

func (c *oktaClient) paginate(path string, handle func([]byte) error) error {
	next := c.base.ResolveReference(&url.URL{Path: path}).String()
	for next != "" {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "SSWS "+c.token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		body, err := readAll(resp)
		if err != nil {
			_ = resp.Body.Close()
			return err
		}
		if resp.StatusCode >= 400 {
			_ = resp.Body.Close()
			return fmt.Errorf("okta http %d", resp.StatusCode)
		}
		if err := handle(body); err != nil {
			_ = resp.Body.Close()
			return err
		}
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		next = parseNextLink(link)
	}
	return nil
}

func parseNextLink(link string) string {
	if link == "" {
		return ""
	}
	parts := strings.Split(link, ",")
	for _, p := range parts {
		if !strings.Contains(p, "rel=\"next\"") {
			continue
		}
		start := strings.Index(p, "<")
		end := strings.Index(p, ">")
		if start == -1 || end == -1 || end <= start+1 {
			continue
		}
		return strings.TrimSpace(p[start+1 : end])
	}
	return ""
}

func isPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "http 403") || strings.Contains(msg, "http 404")
}

func readAll(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
