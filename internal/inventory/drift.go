package inventory

import (
	"sort"

	"aman/internal/env"
)

type DriftReport struct {
	AddedHosts       []env.Host          `json:"added_hosts"`
	RemovedHosts     []env.Host          `json:"removed_hosts"`
	AddedIdentities  []env.Identity      `json:"added_identities"`
	RemovedIdentites []env.Identity      `json:"removed_identities"`
	AddedTrusts      []env.TrustBoundary `json:"added_trusts"`
	RemovedTrusts    []env.TrustBoundary `json:"removed_trusts"`
}

func DiffEnv(before env.Environment, after env.Environment) DriftReport {
	bHosts := mapHostsByID(before.Hosts)
	aHosts := mapHostsByID(after.Hosts)
	bIds := mapIdentitiesByID(before.Identities)
	aIds := mapIdentitiesByID(after.Identities)
	bTrusts := mapTrustsByID(before.TrustBoundaries)
	aTrusts := mapTrustsByID(after.TrustBoundaries)

	rep := DriftReport{
		AddedHosts:       diffHosts(nil, aHosts, bHosts),
		RemovedHosts:     diffHosts(nil, bHosts, aHosts),
		AddedIdentities:  diffIdentities(nil, aIds, bIds),
		RemovedIdentites: diffIdentities(nil, bIds, aIds),
		AddedTrusts:      diffTrusts(nil, aTrusts, bTrusts),
		RemovedTrusts:    diffTrusts(nil, bTrusts, aTrusts),
	}
	return sortDrift(rep)
}

func mapHostsByID(in []env.Host) map[string]env.Host {
	out := map[string]env.Host{}
	for _, h := range in {
		out[h.ID] = h
	}
	return out
}

func mapIdentitiesByID(in []env.Identity) map[string]env.Identity {
	out := map[string]env.Identity{}
	for _, h := range in {
		out[h.ID] = h
	}
	return out
}

func mapTrustsByID(in []env.TrustBoundary) map[string]env.TrustBoundary {
	out := map[string]env.TrustBoundary{}
	for _, h := range in {
		out[h.ID] = h
	}
	return out
}

func diffHosts(out []env.Host, a map[string]env.Host, b map[string]env.Host) []env.Host {
	for id, h := range a {
		if _, ok := b[id]; !ok {
			out = append(out, h)
		}
	}
	return out
}

func diffIdentities(out []env.Identity, a map[string]env.Identity, b map[string]env.Identity) []env.Identity {
	for id, h := range a {
		if _, ok := b[id]; !ok {
			out = append(out, h)
		}
	}
	return out
}

func diffTrusts(out []env.TrustBoundary, a map[string]env.TrustBoundary, b map[string]env.TrustBoundary) []env.TrustBoundary {
	for id, h := range a {
		if _, ok := b[id]; !ok {
			out = append(out, h)
		}
	}
	return out
}

func sortDrift(rep DriftReport) DriftReport {
	sort.Slice(rep.AddedHosts, func(i, j int) bool { return rep.AddedHosts[i].ID < rep.AddedHosts[j].ID })
	sort.Slice(rep.RemovedHosts, func(i, j int) bool { return rep.RemovedHosts[i].ID < rep.RemovedHosts[j].ID })
	sort.Slice(rep.AddedIdentities, func(i, j int) bool { return rep.AddedIdentities[i].ID < rep.AddedIdentities[j].ID })
	sort.Slice(rep.RemovedIdentites, func(i, j int) bool { return rep.RemovedIdentites[i].ID < rep.RemovedIdentites[j].ID })
	sort.Slice(rep.AddedTrusts, func(i, j int) bool { return rep.AddedTrusts[i].ID < rep.AddedTrusts[j].ID })
	sort.Slice(rep.RemovedTrusts, func(i, j int) bool { return rep.RemovedTrusts[i].ID < rep.RemovedTrusts[j].ID })
	return rep
}
