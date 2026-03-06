package v1alpha1

import "fmt"

// Validate performs checks against values of the submitted AuditConfig
func (a *AuditConfig) Validate() error {
	// Check that maximum log event size does not exceed limit and minimum
	if a.Messages.MaxEventSize != nil && (*a.Messages.MaxEventSize < AuditLogMinimumSizeEvent || *a.Messages.MaxEventSize > AuditLogMaximumSizeEvent) {
		return fmt.Errorf("messages.maxEventSize has to be greater than %d and lower than %d", AuditLogMinimumSizeEvent, AuditLogMaximumSizeEvent)
	}

	return nil
}
