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

package majordomo

import (
	"context"

	"github.com/attestantio/go-certmanager/fetcher"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
)

// Fetcher implements fetcher.Fetcher using go-majordomo for flexible certificate retrieval.
type Fetcher struct {
	majordomo majordomo.Service
}

var _ fetcher.Fetcher = (*Fetcher)(nil)

// module-wide log.
var log zerolog.Logger

// New creates a new majordomo fetcher.
func New(ctx context.Context, params ...Parameter) (*Fetcher, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "certmanager").Str("impl", "fetcher").Str("type", "majordomo").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	return &Fetcher{
		majordomo: parameters.majordomo,
	}, nil
}

// Fetch implements fetcher.Fetcher.
func (f *Fetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	return f.majordomo.Fetch(ctx, uri)
}
