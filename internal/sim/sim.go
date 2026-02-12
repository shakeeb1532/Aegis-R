package sim

import (
	"fmt"
	"math/rand"
	"time"

	"aman/internal/model"
)

var eventTypes = []string{
	"email_attachment_open",
	"macro_execution",
	"beacon_outbound",
	"process_creation",
	"lolbin_execution",
	"lsass_access",
	"remote_service_creation",
	"network_logon",
	"new_inbound_admin_protocol",
	"token_manipulation",
	"admin_group_change",
	"valid_account_login",
	"password_spray",
	"credential_stuffing",
	"account_manipulation",
	"auth_process_modify",
	"registry_run_key",
	"service_install",
	"scheduled_task",
	"dns_tunneling",
	"app_layer_c2",
	"disable_logging",
	"cloud_firewall_change",
	"data_staging",
	"large_outbound_transfer",
	"exfil_web_service",
	"impossible_travel",
	"new_device_login",
	"mfa_disabled",
	"token_refresh_anomaly",
	"phish_link_click",
	"oauth_consent",
	"mailbox_rule_create",
	"forwarding_rule_set",
	"mass_file_rename",
	"shadow_copy_delete",
	"encrypt_activity",
	"bulk_download",
	"policy_bypass",
	"unusual_access_scope",
	"ci_runner_compromise",
	"artifact_tamper",
	"signing_key_use",
	"role_assume",
	"sts_token_abuse",
	"trust_policy_change",
	"new_admin_role",
	"oauth_app_grant",
	"admin_2fa_disable",
	"domain_fronting",
	"tor_exit",
	"dns_tunnel",
}

func Synthetic(seed int64, count int) []model.Event {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	//nolint:gosec // deterministic synthetic data generation
	// #nosec G404
	rng := rand.New(rand.NewSource(seed))
	base := time.Now().UTC().Add(-2 * time.Hour)
	events := make([]model.Event, 0, count)
	for i := 0; i < count; i++ {
		typeIdx := rng.Intn(len(eventTypes))
		e := model.Event{
			ID:   randID(rng),
			Time: base.Add(time.Duration(i) * time.Minute),
			Host: hostName(rng),
			User: userName(rng),
			Type: eventTypes[typeIdx],
			Details: map[string]interface{}{
				"src_ip": randomIP(rng),
				"dst_ip": randomIP(rng),
			},
		}
		events = append(events, e)
	}
	// Inject a coherent chain to exercise feasibility
	events = append(events,
		model.Event{ID: randID(rng), Time: base.Add(3 * time.Hour), Host: "host-1", User: "alice", Type: "email_attachment_open"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 2*time.Minute), Host: "host-1", User: "alice", Type: "macro_execution"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 5*time.Minute), Host: "host-1", User: "alice", Type: "beacon_outbound"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 10*time.Minute), Host: "host-1", User: "alice", Type: "token_manipulation"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 12*time.Minute), Host: "host-1", User: "alice", Type: "admin_group_change"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 15*time.Minute), Host: "host-1", User: "alice", Type: "lsass_access"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 20*time.Minute), Host: "host-1", User: "alice", Type: "remote_service_creation"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 25*time.Minute), Host: "host-2", User: "alice", Type: "network_logon"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 40*time.Minute), Host: "host-2", User: "alice", Type: "data_staging"},
		model.Event{ID: randID(rng), Time: base.Add(3*time.Hour + 45*time.Minute), Host: "host-2", User: "alice", Type: "large_outbound_transfer"},
	)
	return events
}

func randID(rng *rand.Rand) string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

func randomIP(rng *rand.Rand) string {
	return fmtIP(rng.Intn(223)+1, rng.Intn(255), rng.Intn(255), rng.Intn(255))
}

func fmtIP(a, b, c, d int) string {
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func hostName(rng *rand.Rand) string {
	return fmt.Sprintf("host-%d", rng.Intn(5)+1)
}

func userName(rng *rand.Rand) string {
	users := []string{"alice", "bob", "carol", "dave"}
	return users[rng.Intn(len(users))]
}
