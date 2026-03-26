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

package san_test

import (
	"strings"
	"testing"

	"github.com/attestantio/go-certmanager/san"
	"github.com/stretchr/testify/require"
)

func TestValidateDNSName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		// Valid cases.
		{
			name:  "Simple domain",
			input: "example.com",
		},
		{
			name:  "Subdomain with hyphens",
			input: "validator-01.prod.example.com",
		},
		{
			name:  "Single label",
			input: "localhost",
		},
		{
			name:  "Wildcard",
			input: "*.example.com",
		},
		{
			name:  "Max length label",
			input: strings.Repeat("a", 63) + ".com",
		},
		{
			name:  "Max total length",
			input: strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 60),
		},
		{
			name:  "Digits only",
			input: "123.456.com",
		},
		{
			name:  "Trailing dot",
			input: "example.com.",
		},

		// Invalid cases.
		{
			name:    "Empty",
			input:   "",
			wantErr: san.ErrDNSNameEmpty,
		},
		{
			name:    "Too long",
			input:   strings.Repeat(strings.Repeat("a", 63)+".", 4) + "a",
			wantErr: san.ErrDNSNameTooLong,
		},
		{
			name:    "Label too long",
			input:   strings.Repeat("a", 64) + ".com",
			wantErr: san.ErrDNSLabelTooLong,
		},
		{
			name:    "Starts with hyphen",
			input:   "-invalid.com",
			wantErr: san.ErrDNSLabelInvalidChar,
		},
		{
			name:    "Ends with hyphen",
			input:   "invalid-.com",
			wantErr: san.ErrDNSLabelInvalidChar,
		},
		{
			name:    "Special characters",
			input:   "inv@lid.com",
			wantErr: san.ErrDNSLabelInvalidChar,
		},
		{
			name:    "Double dot",
			input:   "example..com",
			wantErr: san.ErrDNSLabelEmpty,
		},
		{
			name:    "Wildcard not first",
			input:   "foo.*.com",
			wantErr: san.ErrDNSWildcardInvalid,
		},
		{
			name:    "Partial wildcard",
			input:   "*foo.com",
			wantErr: san.ErrDNSWildcardInvalid,
		},
		{
			name:    "IPv4 address",
			input:   "192.168.1.1",
			wantErr: san.ErrDNSNameIsIPAddress,
		},
		{
			name:    "IPv6 address",
			input:   "::1",
			wantErr: san.ErrDNSNameIsIPAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := san.ValidateDNSName(tt.input)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
