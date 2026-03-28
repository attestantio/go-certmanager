// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package san

import (
	"errors"
	"net"
	"strings"
)

// Sentinel errors for DNS name validation.
var (
	ErrDNSNameEmpty        = errors.New("DNS name is empty")
	ErrDNSNameTooLong      = errors.New("DNS name exceeds 253 characters")
	ErrDNSLabelTooLong     = errors.New("DNS label exceeds 63 characters")
	ErrDNSLabelEmpty       = errors.New("DNS label is empty")
	ErrDNSLabelInvalidChar = errors.New("DNS label contains invalid characters")
	ErrDNSWildcardInvalid  = errors.New("invalid wildcard DNS name")
	ErrDNSNameIsIPAddress  = errors.New("DNS name is an IP address")
)

// ValidateDNSName validates a DNS name according to RFC 1035 label rules.
// Single-label names (e.g., "localhost") are accepted for internal/development use,
// even though RFC 6125 Section 6.4.4 recommends against them as reference identifiers.
// It returns a sentinel error describing the validation failure, or nil if the name is valid.
func ValidateDNSName(name string) error {
	if name == "" {
		return ErrDNSNameEmpty
	}

	// Trim trailing dot for validation purposes.
	validated := strings.TrimSuffix(name, ".")

	// Reject IP addresses.
	if net.ParseIP(validated) != nil {
		return ErrDNSNameIsIPAddress
	}

	// Check total length.
	if len(validated) > 253 {
		return ErrDNSNameTooLong
	}

	// Split into labels and validate each.
	labels := strings.Split(validated, ".")
	for i, label := range labels {
		if label == "" {
			return ErrDNSLabelEmpty
		}

		if len(label) > 63 {
			return ErrDNSLabelTooLong
		}

		// Handle wildcard labels.
		if strings.Contains(label, "*") {
			if i != 0 || label != "*" {
				return ErrDNSWildcardInvalid
			}

			continue
		}

		// Validate label characters.
		if !isAlphanumeric(label[0]) || !isAlphanumeric(label[len(label)-1]) {
			return ErrDNSLabelInvalidChar
		}

		for j := 1; j < len(label)-1; j++ {
			if !isAlphanumeric(label[j]) && label[j] != '-' {
				return ErrDNSLabelInvalidChar
			}
		}
	}

	return nil
}

// isAlphanumeric returns true if the byte is a letter or digit.
func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
