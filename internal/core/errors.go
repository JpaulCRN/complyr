package core

import (
	"fmt"
	"runtime"
	"time"
)

// Custom error types for better error handling and recovery

type ScanError struct {
	Phase   string
	Message string
	Err     error
	Stack   string
}

func (e *ScanError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("scan error in %s: %s: %v", e.Phase, e.Message, e.Err)
	}
	return fmt.Sprintf("scan error in %s: %s", e.Phase, e.Message)
}

func (e *ScanError) Unwrap() error {
	return e.Err
}

type DependencyParseError struct {
	File    string
	Line    int
	Content string
	Err     error
}

func (e *DependencyParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("dependency parse error in %s at line %d: %v", e.File, e.Line, e.Err)
	}
	return fmt.Sprintf("dependency parse error in %s: %v", e.File, e.Err)
}

func (e *DependencyParseError) Unwrap() error {
	return e.Err
}

type CVEScanError struct {
	Package   string
	Ecosystem string
	Reason    string
	Err       error
}

func (e *CVEScanError) Error() string {
	return fmt.Sprintf("CVE scan error for %s in %s ecosystem: %s: %v", e.Package, e.Ecosystem, e.Reason, e.Err)
}

func (e *CVEScanError) Unwrap() error {
	return e.Err
}

type ValidationError struct {
	Field   string
	Value   string
	Reason  string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field %s with value '%s': %s", e.Field, e.Value, e.Reason)
}

// Error creation helpers with stack traces for debugging

func NewScanError(phase string, message string, err error) *ScanError {
	return &ScanError{
		Phase:   phase,
		Message: message,
		Err:     err,
		Stack:   getStackTrace(),
	}
}

func NewDependencyParseError(file string, line int, content string, err error) *DependencyParseError {
	return &DependencyParseError{
		File:    file,
		Line:    line,
		Content: content,
		Err:     err,
	}
}

func NewCVEScanError(pkg, ecosystem, reason string, err error) *CVEScanError {
	return &CVEScanError{
		Package:   pkg,
		Ecosystem: ecosystem,
		Reason:    reason,
		Err:       err,
	}
}

func NewValidationError(field, value, reason string) *ValidationError {
	return &ValidationError{
		Field:  field,
		Value:  value,
		Reason: reason,
	}
}

func getStackTrace() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// Recovery and graceful degradation helpers

type RecoveryHandler struct {
	Phase     string
	Critical  bool
	Callback  func(error)
}

func WithRecovery(phase string, critical bool, callback func(error)) *RecoveryHandler {
	return &RecoveryHandler{
		Phase:    phase,
		Critical: critical,
		Callback: callback,
	}
}

func (r *RecoveryHandler) Execute(fn func() error) error {
	defer func() {
		if rec := recover(); rec != nil {
			var err error
			if e, ok := rec.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("panic: %v", rec)
			}

			scanErr := NewScanError(r.Phase, "recovered from panic", err)
			if r.Callback != nil {
				r.Callback(scanErr)
			}

			if r.Critical {
				panic(scanErr)
			}
		}
	}()

	return fn()
}

// Validation helpers

func ValidateProjectPath(path string) error {
	if path == "" {
		return NewValidationError("path", path, "path cannot be empty")
	}

	if len(path) > 1000 {
		return NewValidationError("path", path, "path too long")
	}

	return nil
}

func ValidateTRL(trl int) error {
	if trl < 1 || trl > 9 {
		return NewValidationError("trl", fmt.Sprintf("%d", trl), "TRL must be between 1 and 9")
	}
	return nil
}

func ValidatePackageName(name string) error {
	if name == "" {
		return NewValidationError("package_name", name, "package name cannot be empty")
	}

	if len(name) > 200 {
		return NewValidationError("package_name", name, "package name too long")
	}

	// Basic validation - could be enhanced with specific rules per ecosystem
	if len(name) < 2 {
		return NewValidationError("package_name", name, "package name too short")
	}

	return nil
}

// Error aggregation for batch operations

type ErrorCollector struct {
	errors []error
	phase  string
}

func NewErrorCollector(phase string) *ErrorCollector {
	return &ErrorCollector{
		errors: make([]error, 0),
		phase:  phase,
	}
}

func (ec *ErrorCollector) Add(err error) {
	if err != nil {
		ec.errors = append(ec.errors, err)
	}
}

func (ec *ErrorCollector) HasErrors() bool {
	return len(ec.errors) > 0
}

func (ec *ErrorCollector) ErrorCount() int {
	return len(ec.errors)
}

func (ec *ErrorCollector) GetErrors() []error {
	return ec.errors
}

func (ec *ErrorCollector) GetAggregatedError() error {
	if !ec.HasErrors() {
		return nil
	}

	if len(ec.errors) == 1 {
		return NewScanError(ec.phase, "single error occurred", ec.errors[0])
	}

	return NewScanError(ec.phase, fmt.Sprintf("multiple errors occurred (%d total)", len(ec.errors)), nil)
}

// Retry logic for network operations

type RetryConfig struct {
	MaxAttempts int
	BackoffMs   int
	Condition   func(error) bool
}

func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		BackoffMs:   1000,
		Condition: func(err error) bool {
			// Retry on network errors, timeouts, or rate limiting
			errStr := err.Error()
			return contains(errStr, "timeout") ||
				   contains(errStr, "connection") ||
				   contains(errStr, "rate limit") ||
				   contains(errStr, "429")
		},
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		   (len(s) > len(substr) &&
		   (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		   findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func WithRetry(config RetryConfig, operation func() error) error {
	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		if attempt < config.MaxAttempts && config.Condition(err) {
			// Simple linear backoff
			time.Sleep(time.Duration(config.BackoffMs*attempt) * time.Millisecond)
			continue
		}

		break
	}

	return lastErr
}