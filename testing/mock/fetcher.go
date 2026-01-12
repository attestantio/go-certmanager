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
	"errors"
)

// Fetcher is a mock fetcher implementation for testing.
type Fetcher struct {
	data map[string][]byte
	err  error
}

// NewFetcher creates a new mock fetcher with preset URI-to-data mappings.
// The data map should contain URIs as keys and certificate/key data as values.
//
// Example usage:
//
//	fetcher := mock.NewFetcher(map[string][]byte{
//	    "file:///path/to/cert.pem": []byte(testing.Client01Crt),
//	    "file:///path/to/cert.key": []byte(testing.Client01Key),
//	})
func NewFetcher(data map[string][]byte) *Fetcher {
	return &Fetcher{data: data}
}

// NewFetcherWithError creates a mock fetcher that always returns the specified error.
// Useful for testing error handling in certificate management code.
func NewFetcherWithError(err error) *Fetcher {
	return &Fetcher{err: err}
}

// Fetch implements fetcher.Fetcher.
// Returns the preset data for the given URI, or an error if configured to fail.
func (f *Fetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	data, ok := f.data[uri]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}
