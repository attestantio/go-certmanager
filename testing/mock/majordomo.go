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

package mock

import (
	"context"
	"fmt"

	"github.com/wealdtech/go-majordomo"
)

// Majordomo is a mock majordomo implementation for testing.
type Majordomo struct {
	data map[string][]byte
	err  error
}

var _ majordomo.Service = (*Majordomo)(nil)

// NewMajordomo creates a new mock majordomo with preset URI-to-data mappings.
// The data map should contain URIs as keys and certificate/key data as values.
//
// Example usage:
//
//	majordomoSvc := mock.NewMajordomo(map[string][]byte{
//	    "file:///path/to/cert.pem": []byte(testing.Client01Crt),
//	    "file:///path/to/cert.key": []byte(testing.Client01Key),
//	})
func NewMajordomo(data map[string][]byte) *Majordomo {
	return &Majordomo{data: data}
}

// NewMajordomoWithError creates a mock majordomo that always returns the specified error.
// Useful for testing error handling in certificate management code.
func NewMajordomoWithError(err error) *Majordomo {
	return &Majordomo{err: err}
}

// Fetch implements majordomo.Service.
// Returns the preset data for the given URI, or an error if configured to fail.
func (m *Majordomo) Fetch(_ context.Context, uri string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	data, ok := m.data[uri]
	if !ok {
		return nil, fmt.Errorf("URI %q not found in mock", uri)
	}
	return data, nil
}
