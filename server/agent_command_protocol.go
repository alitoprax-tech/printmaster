package main

func allowedAgentCommand(command string) bool {
	switch command {
	case "check_update", "cancel_update", "force_update", "restart":
		return true
	default:
		return false
	}
}

func reservedAgentCommandField(field string) bool {
	switch field {
	case "command", "message_id", "job_id", "issued_at", "expires_at":
		return true
	default:
		return false
	}
}
