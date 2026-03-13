package integration

import (
	"encoding/json"
	"strconv"
	"strings"

	"aman/internal/model"
)

type windowsSecurityEvent struct {
	EventID            interface{}            `json:"EventID"`
	EventCode          interface{}            `json:"EventCode"`
	EventTime          string                 `json:"EventTime"`
	TimeCreated        string                 `json:"TimeCreated"`
	RawTime            string                 `json:"_time"`
	Hostname           string                 `json:"Hostname"`
	Computer           string                 `json:"Computer"`
	ComputerName       string                 `json:"ComputerName"`
	Channel            string                 `json:"Channel"`
	ChannelName        string                 `json:"LogName"`
	Message            string                 `json:"Message"`
	EventData          map[string]interface{} `json:"EventData"`
	Details            map[string]interface{} `json:"details"`
	TargetUserName     interface{}            `json:"TargetUserName"`
	SubjectUserName    interface{}            `json:"SubjectUserName"`
	IpAddress          interface{}            `json:"IpAddress"`
	IpPort             interface{}            `json:"IpPort"`
	Workstation        interface{}            `json:"WorkstationName"`
	AuthenticationPkg  interface{}            `json:"AuthenticationPackageName"`
	AccountName        interface{}            `json:"Account_Name"`
	SimpleAccountName  interface{}            `json:"AccountName"`
	AccountDomain      interface{}            `json:"Account_Domain"`
	LogonType          interface{}            `json:"Logon_Type"`
	LogonTypeName      interface{}            `json:"LogonType"`
	LogonID            interface{}            `json:"Logon_ID"`
	SourceNetworkAddr  interface{}            `json:"Source_Network_Address"`
	WorkstationName    interface{}            `json:"Workstation_Name"`
	AuthPackage        interface{}            `json:"Authentication_Package"`
	Status             interface{}            `json:"Status"`
	SubStatus          interface{}            `json:"SubStatus"`
	ProcessName        interface{}            `json:"Process_Name"`
	ProcessCommandLine interface{}            `json:"Process_Command_Line"`
	NewProcessName     interface{}            `json:"New_Process_Name"`
	RecordNumber       interface{}            `json:"RecordNumber"`
	LogonGUID          interface{}            `json:"Logon_GUID"`
}

func mapWindowsSecurityJSON(raw []byte) ([]model.Event, error) {
	var in []windowsSecurityEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in)*2)
	for _, e := range in {
		details := map[string]interface{}{
			"channel": firstNonEmpty(e.Channel, e.ChannelName),
			"message": e.Message,
			"logon_type": firstNonEmpty(
				fieldString(e.EventData, "LogonType"),
				fieldString(e.EventData, "LogonTypeName"),
				fieldStringAny(map[string]interface{}{"LogonType": e.LogonTypeName}, "LogonType"),
				fieldStringAny(map[string]interface{}{"LogonType": e.LogonType}, "LogonType"),
				fieldStringAny(map[string]interface{}{
					"Logon_Type": e.LogonType,
				}, "Logon_Type"),
			),
			"logon_id": firstNonEmpty(
				fieldStringAny(e.EventData, "TargetLogonId", "SubjectLogonId", "LogonId"),
				fieldStringAny(map[string]interface{}{"TargetLogonId": e.LogonID}, "TargetLogonId"),
				fieldStringAny(map[string]interface{}{"Logon_ID": e.LogonID}, "Logon_ID"),
			),
			"source_ip": firstNonEmpty(
				fieldStringAny(e.EventData, "IpAddress", "SourceNetworkAddress", "ClientAddress"),
				fieldStringAny(map[string]interface{}{"IpAddress": e.IpAddress}, "IpAddress"),
				fieldStringAny(map[string]interface{}{"Source_Network_Address": e.SourceNetworkAddr}, "Source_Network_Address"),
			),
			"source_host": firstNonEmpty(
				fieldStringAny(e.EventData, "WorkstationName", "IpHostname", "SourceWorkstation"),
				fieldStringAny(map[string]interface{}{"WorkstationName": e.Workstation}, "WorkstationName"),
				fieldStringAny(map[string]interface{}{"Workstation_Name": e.WorkstationName}, "Workstation_Name"),
			),
			"auth_package": firstNonEmpty(
				fieldStringAny(e.EventData, "AuthenticationPackageName", "LmPackageName"),
				fieldStringAny(map[string]interface{}{"AuthenticationPackageName": e.AuthenticationPkg}, "AuthenticationPackageName"),
				fieldStringAny(map[string]interface{}{"Authentication_Package": e.AuthPackage}, "Authentication_Package"),
			),
			"status": firstNonEmpty(
				fieldString(e.EventData, "Status"),
				fieldString(e.EventData, "FailureReason"),
				fieldStringAny(map[string]interface{}{"Status": e.Status}, "Status"),
			),
			"sub_status":          firstNonEmpty(fieldStringAny(e.EventData, "SubStatus", "FailureSubStatus"), fieldStringAny(map[string]interface{}{"SubStatus": e.SubStatus}, "SubStatus")),
			"process_guid":        fieldStringAny(e.EventData, "ProcessGuid"),
			"parent_process_guid": fieldStringAny(e.EventData, "ParentProcessGuid"),
			"process_name": firstNonEmpty(
				fieldStringAny(e.EventData, "ProcessName", "NewProcessName"),
				fieldStringAny(map[string]interface{}{"Process_Name": e.ProcessName, "New_Process_Name": e.NewProcessName}, "Process_Name", "New_Process_Name"),
			),
			"command_line": firstNonEmpty(
				fieldStringAny(e.EventData, "CommandLine", "ProcessCommandLine"),
				fieldStringAny(map[string]interface{}{"Process_Command_Line": e.ProcessCommandLine}, "Process_Command_Line"),
			),
			"logon_guid": fieldStringAny(map[string]interface{}{"Logon_GUID": e.LogonGUID}, "Logon_GUID"),
		}
		merge(details, e.Details)
		merge(details, e.EventData)

		host := firstNonEmpty(e.Hostname, e.Computer, e.ComputerName)
		user := firstNonEmpty(
			fieldStringAny(e.EventData, "TargetUserName", "SubjectUserName", "AccountName"),
			fieldStringAny(map[string]interface{}{"TargetUserName": e.TargetUserName, "SubjectUserName": e.SubjectUserName}, "TargetUserName", "SubjectUserName"),
			fieldStringAny(map[string]interface{}{"Account_Name": e.AccountName}, "Account_Name"),
			fieldStringAny(map[string]interface{}{"AccountName": e.SimpleAccountName}, "AccountName"),
		)
		when := parseTime(firstNonEmpty(e.EventTime, e.TimeCreated, e.RawTime))
		eventID := windowsSecurityEventCode(e)
		types := mapWindowsSecurityTypes(eventID, details)
		if len(types) == 0 {
			types = []string{"windows_security_event"}
		}
		recordID := firstNonEmpty(fieldStringAny(e.EventData, "EventRecordID", "RecordNumber"), fieldStringAny(map[string]interface{}{"RecordNumber": e.RecordNumber}, "RecordNumber"), e.EventTime, e.TimeCreated, e.RawTime)
		for i, typ := range types {
			out = append(out, model.Event{
				ID:      hashEventID("windows-security", recordID, strconv.Itoa(i), typ, host, user),
				Time:    when,
				Host:    host,
				User:    user,
				Type:    typ,
				Details: details,
			})
		}
	}
	return out, nil
}

func mapWindowsSecurityTypes(eventID int, details map[string]interface{}) []string {
	logonType := strings.TrimSpace(fieldStringAny(details, "logon_type", "LogonType", "LogonTypeName"))
	status := strings.ToLower(firstNonEmpty(fieldString(details, "status"), fieldString(details, "sub_status")))
	message := strings.ToLower(fieldString(details, "message"))

	switch eventID {
	case 4624:
		types := []string{"signin_success", "valid_account_login"}
		if isRemoteLogonType(logonType) {
			types = append(types, "network_logon")
		}
		return dedupeTypes(types)
	case 4625:
		types := []string{classifyWindowsSignInFailure(status, message)}
		if isRemoteLogonType(logonType) {
			types = append(types, "network_logon_failure", "admin_protocol_denied")
		}
		return dedupeTypes(types)
	case 4720:
		return []string{"new_admin_account"}
	case 4728, 4732:
		return []string{"admin_group_change"}
	case 4648:
		types := []string{"valid_account_login", "explicit_credential_use"}
		if isRemoteLogonType(logonType) {
			types = append(types, "network_logon")
		}
		return dedupeTypes(types)
	case 4672:
		return []string{"privileged_logon"}
	case 4776:
		if strings.TrimSpace(strings.ToLower(firstNonEmpty(
			fieldStringAny(details, "status", "Status"),
			fieldStringAny(details, "sub_status", "SubStatus"),
		))) == "0x0" {
			return []string{"signin_success", "valid_account_login"}
		}
		return []string{"signin_failed_auth"}
	case 4768, 4769:
		return []string{"kerberos_ticket"}
	case 4698, 4702:
		return []string{"scheduled_task", "schtasks_create"}
	case 4699:
		return []string{"scheduled_task_deleted"}
	case 4688:
		types := []string{"process_creation"}
		image := strings.ToLower(fieldStringAny(details, "process_name", "Process_Name", "New_Process_Name"))
		cmd := strings.ToLower(fieldStringAny(details, "command_line", "Process_Command_Line"))
		if containsAny(image, "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "wmic.exe") ||
			containsAny(cmd, "mshta", "rundll32", "regsvr32", "certutil", "wmic") {
			types = append(types, "lolbin_execution")
		}
		if containsAny(image, "powershell.exe") || containsAny(cmd, "powershell", "pwsh") {
			types = append(types, "script_execution")
			if containsAny(cmd, "-enc", "encodedcommand") {
				types = append(types, "encoded_powershell", "encoded_command")
			}
		}
		if containsAny(cmd, "lsass") {
			types = append(types, "lsass_access")
		}
		return dedupeTypes(types)
	case 1102:
		return []string{"disable_logging"}
	case 7045:
		return []string{"service_install"}
	default:
		return nil
	}
}

func classifyWindowsSignInFailure(status string, message string) string {
	switch {
	case containsAny(status, "0xc000006e", "0xc0000070", "0xc0000413"), containsAny(message, "policy", "logon restriction", "workstation restriction"):
		return "signin_denied_policy"
	case containsAny(status, "0xc0000072", "0xc0000234"), containsAny(message, "account disabled", "account locked"):
		return "signin_denied_account_state"
	default:
		return "signin_failed_auth"
	}
}

func isRemoteLogonType(v string) bool {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "3", "network", "10", "remoteinteractive", "remote interactive":
		return true
	default:
		return false
	}
}

func windowsSecurityEventCode(e windowsSecurityEvent) int {
	for _, v := range []interface{}{e.EventID, e.EventCode} {
		switch t := v.(type) {
		case float64:
			return int(t)
		case string:
			i, _ := strconv.Atoi(strings.TrimSpace(t))
			if i != 0 {
				return i
			}
		}
	}
	return 0
}
