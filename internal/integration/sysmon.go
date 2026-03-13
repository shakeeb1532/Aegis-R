package integration

import (
	"encoding/json"
	"strconv"
	"strings"

	"aman/internal/model"
)

type sysmonEvent struct {
	EventID           interface{}            `json:"EventID"`
	EventCode         interface{}            `json:"EventCode"`
	EventTime         string                 `json:"EventTime"`
	TimeCreated       string                 `json:"TimeCreated"`
	UtcTime           string                 `json:"UtcTime"`
	RawTime           string                 `json:"_time"`
	Hostname          string                 `json:"Hostname"`
	Computer          string                 `json:"Computer"`
	Host              string                 `json:"Host"`
	User              string                 `json:"User"`
	Image             string                 `json:"Image"`
	ParentImage       string                 `json:"ParentImage"`
	CommandLine       string                 `json:"CommandLine"`
	ProcessGuid       string                 `json:"ProcessGuid"`
	ParentProcessGuid string                 `json:"ParentProcessGuid"`
	RuleName          string                 `json:"RuleName"`
	TargetObject      string                 `json:"TargetObject"`
	TargetFilename    string                 `json:"TargetFilename"`
	TargetImage       string                 `json:"TargetImage"`
	SourceProcessGUID string                 `json:"SourceProcessGUID"`
	SourceImage       string                 `json:"SourceImage"`
	GrantedAccess     string                 `json:"GrantedAccess"`
	Channel           string                 `json:"Channel"`
	SourceName        string                 `json:"SourceName"`
	Message           string                 `json:"Message"`
	Details           interface{} `json:"details"`
	UpperDetails      interface{} `json:"Details"`
	EventData         map[string]interface{} `json:"EventData"`
}

func mapSysmonJSON(raw []byte) ([]model.Event, error) {
	var in []sysmonEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in)*2)
	for _, e := range in {
		baseDetails := map[string]interface{}{
			"image":               firstNonEmpty(e.Image, fieldString(e.EventData, "Image")),
			"parent_image":        firstNonEmpty(e.ParentImage, fieldString(e.EventData, "ParentImage")),
			"command_line":        firstNonEmpty(e.CommandLine, fieldString(e.EventData, "CommandLine")),
			"process_guid":        firstNonEmpty(e.ProcessGuid, fieldString(e.EventData, "ProcessGuid")),
			"parent_process_guid": firstNonEmpty(e.ParentProcessGuid, fieldString(e.EventData, "ParentProcessGuid")),
			"target_object":       firstNonEmpty(e.TargetObject, fieldString(e.EventData, "TargetObject")),
			"target_filename":     firstNonEmpty(e.TargetFilename, fieldString(e.EventData, "TargetFilename")),
			"target_image":        firstNonEmpty(e.TargetImage, fieldString(e.EventData, "TargetImage")),
			"source_process_guid": firstNonEmpty(e.SourceProcessGUID, fieldString(e.EventData, "SourceProcessGUID")),
			"source_image":        firstNonEmpty(e.SourceImage, fieldString(e.EventData, "SourceImage")),
			"granted_access":      firstNonEmpty(e.GrantedAccess, fieldString(e.EventData, "GrantedAccess")),
			"channel":             e.Channel,
			"source_name":         e.SourceName,
			"rule_name":           e.RuleName,
			"message":             e.Message,
		}
		if detailsMap, ok := e.Details.(map[string]interface{}); ok {
			merge(baseDetails, detailsMap)
		}
		if upperDetailsMap, ok := e.UpperDetails.(map[string]interface{}); ok {
			merge(baseDetails, upperDetailsMap)
		}
		merge(baseDetails, e.EventData)

		eventTypes := mapSysmonTypes(e, baseDetails)
		if len(eventTypes) == 0 {
			eventTypes = []string{"sysmon_event"}
		}
		host := firstNonEmpty(e.Hostname, e.Computer, e.Host)
		user := firstNonEmpty(e.User, fieldString(e.EventData, "User"), fieldString(e.EventData, "AccountName"))
		when := parseTime(firstNonEmpty(e.EventTime, e.TimeCreated, e.UtcTime, e.RawTime, fieldString(e.EventData, "UtcTime")))
		eventID := sysmonEventID(e)
		for i, eventType := range eventTypes {
			out = append(out, model.Event{
				ID:      hashEventID(eventID, strconv.Itoa(i), eventType, host, user),
				Time:    when,
				Host:    host,
				User:    user,
				Type:    eventType,
				Details: baseDetails,
			})
		}
	}
	return out, nil
}

func mapSysmonTypes(e sysmonEvent, details map[string]interface{}) []string {
	image := strings.ToLower(fieldStringAny(details, "image", "Image"))
	parent := strings.ToLower(fieldStringAny(details, "parent_image", "ParentImage"))
	cmd := strings.ToLower(fieldStringAny(details, "command_line", "CommandLine"))
	target := strings.ToLower(fieldStringAny(details, "target_object", "TargetObject"))
	targetFile := strings.ToLower(fieldStringAny(details, "target_filename", "TargetFilename"))
	targetImage := strings.ToLower(fieldStringAny(details, "target_image", "TargetImage"))
	message := strings.ToLower(fieldStringAny(details, "message", "Message"))
	ruleName := strings.ToLower(e.RuleName)
	eventID := sysmonEventCode(e)

	switch eventID {
	case 1:
		types := []string{"process_creation"}
		if containsAny(cmd, "schtasks /create", "schtasks.exe /create", "schtasks.exe\t/create", "schtasks\t/create") {
			types = append(types, "schtasks_create")
		}
		if containsAny(image, "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "wmic.exe") ||
			containsAny(cmd, "mshta", "rundll32", "regsvr32", "certutil", "wmic") {
			types = append(types, "lolbin_execution")
		}
		if containsAny(image, "wmic.exe") || containsAny(parent, "wmic.exe") || containsAny(cmd, "wmic ") {
			types = append(types, "wmic_process_create")
		}
		if containsAny(image, "powershell.exe") || containsAny(cmd, "powershell", "pwsh") {
			types = append(types, "script_execution")
			if containsAny(cmd, "-enc", "encodedcommand") {
				types = append(types, "encoded_powershell", "encoded_command")
			}
		}
		if containsAny(image, "psexec", "paexec") || containsAny(parent, "psexec", "paexec") {
			types = append(types, "psexec_execution")
		}
		if containsAny(parent, "winrshost.exe", "wsmprovhost.exe") {
			types = append(types, "new_inbound_admin_protocol")
		}
		if containsAny(cmd, "lsass") {
			types = append(types, "lsass_access")
		}
		return dedupeTypes(types)
	case 3:
		if containsAny(fieldStringAny(details, "DestinationPort", "dest_port"), "3389", "445", "5985", "5986", "22") {
			return []string{"new_inbound_admin_protocol"}
		}
		return []string{"network_connection"}
	case 10:
		granted := strings.ToLower(fieldStringAny(details, "granted_access", "GrantedAccess"))
		if containsAny(targetImage, "lsass.exe") || containsAny(message, "targetimage: c:\\windows\\system32\\lsass.exe") {
			if granted == "" || containsAny(granted, "0x1fffff", "0x1f3fff", "0x143a", "0x1410", "0x1400", "0x1010", "0x1000") {
				return []string{"lsass_access"}
			}
		}
		return []string{"process_access"}
	case 11:
		if containsAny(targetFile, "\\windows\\tasks\\", "\\system32\\tasks\\") {
			return []string{"scheduled_task"}
		}
		if containsAny(targetFile, "\\startup\\", "startup\\") {
			return []string{"persistence_artifact_created"}
		}
		return []string{"file_create"}
	case 13:
		if containsAny(target, "\\run", "\\runonce") {
			return []string{"registry_run_key"}
		}
		return []string{"registry_change"}
	case 19, 20, 21:
		return []string{"wmi_subscription_trigger"}
	case 7045:
		return []string{"service_install"}
	case 1102:
		return []string{"disable_logging"}
	}

	if containsAny(ruleName, "technique_id=t1112") || containsAny(message, "registry value set") {
		if containsAny(target, "\\run", "\\runonce") {
			return []string{"registry_run_key"}
		}
		return []string{"registry_change"}
	}
	if containsAny(message, "the audit log was cleared", "event logging service") {
		return []string{"disable_logging"}
	}
	return nil
}

func sysmonEventCode(e sysmonEvent) int {
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

func sysmonEventID(e sysmonEvent) string {
	return firstNonEmpty(
		fieldString(e.EventData, "EventRecordID"),
		fieldString(e.EventData, "RecordNumber"),
		fieldString(e.EventData, "ProcessGuid"),
		e.ProcessGuid,
		e.EventTime,
		e.TimeCreated,
		e.UtcTime,
		e.RawTime,
	)
}

func dedupeTypes(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, typ := range in {
		if typ == "" || seen[typ] {
			continue
		}
		seen[typ] = true
		out = append(out, typ)
	}
	return out
}
