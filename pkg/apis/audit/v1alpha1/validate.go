package v1alpha1

import "fmt"

// Validate performs checks against values of the submitted AuditConfig
func (a *AuditConfig) Validate() error {
	// Check that maximum log event size does not exceed limit
	if *(a.Messages.MaxEventSize) < 0 || *(a.Messages.MaxEventSize) > AuditLogMaximumSizeEvent {
		return fmt.Errorf("messages.maxEventSize has to be greater than 0 and lower than %d", AuditLogMaximumSizeEvent)
	}

	return nil
}
