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

package fetcher

import "context"

// Fetcher abstracts certificate data retrieval from various sources.
// Implementations can fetch from files, HTTP endpoints, secret vaults, etc.
//
// The URI format is implementation-specific. For example:
//   - File-based: "file:///path/to/cert.pem"
//   - AWS Secrets Manager: "asm://secret-name"
//   - HTTP: "https://example.com/certs/cert.pem"
type Fetcher interface {
	// Fetch retrieves data from the specified URI.
	// Returns the fetched data or an error if the fetch fails.
	Fetch(ctx context.Context, uri string) ([]byte, error)
}
