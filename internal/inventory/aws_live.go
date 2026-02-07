package inventory

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type assumeRolePolicy struct {
	Statement []struct {
		Principal struct {
			AWS     any    `json:"AWS"`
			Service any    `json:"Service"`
			Federated string `json:"Federated"`
		} `json:"Principal"`
	} `json:"Statement"`
}

func (AWSAdapter) Load(cfg AdapterConfig) (Inventory, error) {
	ctx := context.Background()
	opts := []func(*config.LoadOptions) error{}
	if cfg.AWS.Region != "" {
		opts = append(opts, config.WithRegion(cfg.AWS.Region))
	}
	if cfg.AWS.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(cfg.AWS.Profile))
	}
	baseCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return Inventory{}, err
	}
	if cfg.AWS.RoleARN != "" {
		stsClient := sts.NewFromConfig(baseCfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, cfg.AWS.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if cfg.AWS.External != "" {
				o.ExternalID = aws.String(cfg.AWS.External)
			}
		})
		baseCfg.Credentials = aws.NewCredentialsCache(provider)
	}

	inv := Inventory{}
	iamClient := iam.NewFromConfig(baseCfg)
	ec2Client := ec2.NewFromConfig(baseCfg)

	if err := loadIAM(ctx, iamClient, &inv); err != nil {
		return Inventory{}, err
	}
	if err := loadEC2(ctx, ec2Client, &inv); err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

func loadIAM(ctx context.Context, client *iam.Client, inv *Inventory) error {
	userPager := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPager.HasMorePages() {
		page, err := userPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, u := range page.Users {
			inv.AWS.Users = append(inv.AWS.Users, AWSUser{
				ID:        aws.ToString(u.Arn),
				UserName:  aws.ToString(u.UserName),
				PrivLevel: "unknown",
				Tags:      []string{"iam:user"},
			})
		}
	}

	rolePager := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePager.HasMorePages() {
		page, err := rolePager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, r := range page.Roles {
			trusts := parseAssumeRolePolicy(aws.ToString(r.AssumeRolePolicyDocument))
			inv.AWS.Roles = append(inv.AWS.Roles, AWSRole{
				ID:        aws.ToString(r.Arn),
				Name:      aws.ToString(r.RoleName),
				PrivLevel: "unknown",
				Trusts:    trusts,
				Tags:      []string{"iam:role"},
			})
		}
	}
	return nil
}

func loadEC2(ctx context.Context, client *ec2.Client, inv *Inventory) error {
	instPager := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for instPager.HasMorePages() {
		page, err := instPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				tags, name, critical := parseEC2Tags(inst.Tags)
				inv.AWS.Instances = append(inv.AWS.Instances, AWSInstance{
					ID:       aws.ToString(inst.InstanceId),
					Name:     name,
					VPC:      aws.ToString(inst.VpcId),
					Subnet:   aws.ToString(inst.SubnetId),
					Zone:     aws.ToString(inst.Placement.AvailabilityZone),
					Critical: critical,
					Tags:     tags,
				})
			}
		}
	}

	vpcPager := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
	for vpcPager.HasMorePages() {
		page, err := vpcPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, v := range page.Vpcs {
			tags, name, _ := parseEC2Tags(v.Tags)
			inv.AWS.VPCs = append(inv.AWS.VPCs, AWSVPC{ID: aws.ToString(v.VpcId), Name: name, Tags: tags})
		}
	}

	subPager := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	for subPager.HasMorePages() {
		page, err := subPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, s := range page.Subnets {
			tags, _, _ := parseEC2Tags(s.Tags)
			inv.AWS.Subnets = append(inv.AWS.Subnets, AWSSubnet{ID: aws.ToString(s.SubnetId), VPC: aws.ToString(s.VpcId), Zone: aws.ToString(s.AvailabilityZone), Tags: tags})
		}
	}

	sgPager := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for sgPager.HasMorePages() {
		page, err := sgPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, sg := range page.SecurityGroups {
			tags, name, _ := parseEC2Tags(sg.Tags)
			gid := aws.ToString(sg.GroupId)
			inv.AWS.SecurityGroups = append(inv.AWS.SecurityGroups, AWSSecurityGroup{
				ID:      gid,
				Name:    name,
				VPC:     aws.ToString(sg.VpcId),
				Ingress: mapPermsToRules(sg.IpPermissions, gid, "ingress"),
				Egress:  mapPermsToRules(sg.IpPermissionsEgress, gid, "egress"),
				Tags:    tags,
			})
		}
	}
	return nil
}

func parseEC2Tags(tags []ec2types.Tag) ([]string, string, bool) {
	out := []string{}
	name := ""
	critical := false
	for _, t := range tags {
		k := aws.ToString(t.Key)
		v := aws.ToString(t.Value)
		if k == "Name" {
			name = v
		}
		if strings.ToLower(k) == "critical" && strings.ToLower(v) == "true" {
			critical = true
		}
		if k != "" {
			if v != "" {
				out = append(out, k+":"+v)
			} else {
				out = append(out, k)
			}
		}
	}
	return out, name, critical
}

func mapPermsToRules(perms []ec2types.IpPermission, groupID string, direction string) []AWSRule {
	out := []AWSRule{}
	for _, p := range perms {
		proto := aws.ToString(p.IpProtocol)
		if proto == "-1" {
			proto = "all"
		}
		port := portRange(p.FromPort, p.ToPort)
		for _, r := range p.IpRanges {
			if direction == "egress" {
				out = append(out, AWSRule{Source: groupID, Destination: aws.ToString(r.CidrIp), Protocol: proto, Port: port, Notes: direction})
			} else {
				out = append(out, AWSRule{Source: aws.ToString(r.CidrIp), Destination: groupID, Protocol: proto, Port: port, Notes: direction})
			}
		}
		for _, r := range p.Ipv6Ranges {
			if direction == "egress" {
				out = append(out, AWSRule{Source: groupID, Destination: aws.ToString(r.CidrIpv6), Protocol: proto, Port: port, Notes: direction})
			} else {
				out = append(out, AWSRule{Source: aws.ToString(r.CidrIpv6), Destination: groupID, Protocol: proto, Port: port, Notes: direction})
			}
		}
		for _, r := range p.UserIdGroupPairs {
			if direction == "egress" {
				out = append(out, AWSRule{Source: groupID, Destination: "sg:" + aws.ToString(r.GroupId), Protocol: proto, Port: port, Notes: direction})
			} else {
				out = append(out, AWSRule{Source: "sg:" + aws.ToString(r.GroupId), Destination: groupID, Protocol: proto, Port: port, Notes: direction})
			}
		}
	}
	return out
}

func portRange(from *int32, to *int32) string {
	if from == nil && to == nil {
		return "all"
	}
	if from != nil && to != nil {
		if *from == *to {
			return fmtInt(*from)
		}
		return fmtInt(*from) + "-" + fmtInt(*to)
	}
	if from != nil {
		return fmtInt(*from)
	}
	return fmtInt(*to)
}

func fmtInt(v int32) string {
	return strconv.FormatInt(int64(v), 10)
}

func parseAssumeRolePolicy(raw string) []string {
	if raw == "" {
		return nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	var doc assumeRolePolicy
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}
	principals := []string{}
	for _, s := range doc.Statement {
		principals = append(principals, expandPrincipal(s.Principal.AWS)...)
		principals = append(principals, expandPrincipal(s.Principal.Service)...)
		if s.Principal.Federated != "" {
			principals = append(principals, s.Principal.Federated)
		}
	}
	return uniqueStrings(principals)
}

func expandPrincipal(v any) []string {
	switch p := v.(type) {
	case string:
		return []string{p}
	case []interface{}:
		out := []string{}
		for _, item := range p {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
