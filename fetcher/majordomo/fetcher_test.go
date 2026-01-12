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

package majordomo_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-certmanager/fetcher/majordomo"
	majordomostandard "github.com/wealdtech/go-majordomo/standard"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		params  []majordomo.Parameter
		wantErr bool
	}{
		{
			name:    "NoMajordomo",
			params:  []majordomo.Parameter{},
			wantErr: true,
		},
		{
			name: "WithMajordomo",
			params: []majordomo.Parameter{
				majordomo.WithMajordomo(newMajordomo(t)),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := majordomo.New(ctx, tt.params...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func newMajordomo(t *testing.T) *majordomostandard.Service {
	t.Helper()
	svc, err := majordomostandard.New(context.Background())
	if err != nil {
		t.Fatalf("Failed to create majordomo service: %v", err)
	}
	return svc
}
