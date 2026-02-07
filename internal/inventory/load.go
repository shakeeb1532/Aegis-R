package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"aegisr/internal/ops"
)

func Load(path string) (Inventory, error) {
	var inv Inventory
	if path == "" {
		return inv, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return inv, os.ErrInvalid
	}
	info, err := os.Stat(path)
	if err != nil {
		return inv, err
	}
	if info.IsDir() {
		return loadDir(path)
	}
	return loadFile(path)
}

func loadDir(dir string) (Inventory, error) {
	var inv Inventory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return inv, err
	}
	for _, e := range entries {
		if e.IsDir() {
			child := filepath.Join(dir, e.Name())
			childInv, err := loadDir(child)
			if err != nil {
				return inv, err
			}
			inv = merge(inv, childInv)
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		child := filepath.Join(dir, e.Name())
		childInv, err := loadFile(child)
		if err != nil {
			return inv, err
		}
		inv = merge(inv, childInv)
	}
	return inv, nil
}

func loadFile(path string) (Inventory, error) {
	var inv Inventory
	if !ops.IsSafePath(path) {
		return inv, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return inv, err
	}
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(name, "aws"):
		var aws AWSInventory
		if err := json.Unmarshal(data, &aws); err != nil {
			return inv, err
		}
		inv.AWS = aws
	case strings.Contains(name, "okta"):
		var okta OktaInventory
		if err := json.Unmarshal(data, &okta); err != nil {
			return inv, err
		}
		inv.Okta = okta
	case strings.Contains(name, "azure") || strings.Contains(name, "entra"):
		var az AzureInventory
		if err := json.Unmarshal(data, &az); err != nil {
			return inv, err
		}
		inv.Azure = az
	case strings.Contains(name, "gcp"):
		var gcp GCPInventory
		if err := json.Unmarshal(data, &gcp); err != nil {
			return inv, err
		}
		inv.GCP = gcp
	default:
		return inv, nil
	}
	return inv, nil
}

func merge(a Inventory, b Inventory) Inventory {
	if len(b.AWS.Accounts) > 0 || len(b.AWS.Users) > 0 || len(b.AWS.Roles) > 0 || len(b.AWS.Instances) > 0 || len(b.AWS.SecurityGroups) > 0 {
		a.AWS = b.AWS
	}
	if len(b.Okta.Users) > 0 || len(b.Okta.Groups) > 0 || len(b.Okta.Roles) > 0 || len(b.Okta.Apps) > 0 {
		a.Okta = b.Okta
	}
	if len(b.Azure.Users) > 0 || len(b.Azure.Groups) > 0 || len(b.Azure.RoleAssignments) > 0 || len(b.Azure.Networks) > 0 || len(b.Azure.Subnets) > 0 || len(b.Azure.NSGs) > 0 {
		a.Azure = b.Azure
	}
	if len(b.GCP.Users) > 0 || len(b.GCP.ServiceAccounts) > 0 || len(b.GCP.IAMBindings) > 0 || len(b.GCP.Networks) > 0 || len(b.GCP.Subnets) > 0 || len(b.GCP.FirewallRules) > 0 {
		a.GCP = b.GCP
	}
	return a
}

// MergeInventory exposes merge logic for multi-provider refresh.
func MergeInventory(a Inventory, b Inventory) Inventory {
	return merge(a, b)
}
