// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectorRepresentatives(t *testing.T) {
	app := regexp.MustCompile(`^[-a-zA-Z0-9_]*\.app\.test\.local\.?$`)
	api := regexp.MustCompile(`^[-a-zA-Z0-9_]*\.api\.other\.local\.?$`)

	for _, tc := range []struct {
		name      string
		names     []string
		selectors []*regexp.Regexp
		want      []string
	}{
		{
			name:      "no selectors registered",
			names:     []string{"a.app.test.local"},
			selectors: nil,
			want:      nil,
		},
		{
			name:      "no names",
			names:     nil,
			selectors: []*regexp.Regexp{app},
			want:      nil,
		},
		{
			name:      "names matching no selector are dropped",
			names:     []string{"a.unrelated.example.com", "b.unrelated.example.com"},
			selectors: []*regexp.Regexp{app},
			want:      []string{},
		},
		{
			name:      "one selector keeps only the first match",
			names:     []string{"a.app.test.local", "b.app.test.local", "c.app.test.local"},
			selectors: []*regexp.Regexp{app},
			want:      []string{"a.app.test.local"},
		},
		{
			name:      "unmatched names are skipped before a match",
			names:     []string{"x.unrelated.example.com", "b.app.test.local"},
			selectors: []*regexp.Regexp{app},
			want:      []string{"b.app.test.local"},
		},
		{
			name:      "every matched selector keeps a representative",
			names:     []string{"a.app.test.local", "b.app.test.local", "a.api.other.local"},
			selectors: []*regexp.Regexp{app, api},
			want:      []string{"a.app.test.local", "a.api.other.local"},
		},
		{
			name:      "one name covering two selectors is kept once",
			names:     []string{"a.app.test.local", "b.app.test.local"},
			selectors: []*regexp.Regexp{app, app},
			want:      []string{"a.app.test.local"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := selectorRepresentatives(tc.names, tc.selectors)
			require.ElementsMatch(t, tc.want, got)
			require.LessOrEqual(t, len(got), len(tc.selectors),
				"must never retain more names than there are selectors")
		})
	}
}

// TestSelectorRepresentativesBoundedBySelectors is the property that motivates
// the change: what an alive zombie re-inserts into the global cache scales with
// the number of selectors in policy, not with the number of distinct names that
// ever resolved to that IP.
func TestSelectorRepresentativesBoundedBySelectors(t *testing.T) {
	app := regexp.MustCompile(`^[-a-zA-Z0-9_]*\.app\.test\.local\.?$`)

	for _, n := range []int{1000, 20000, 200000} {
		names := make([]string, 0, n)
		for i := range n {
			names = append(names, fmt.Sprintf("n%d.app.test.local", i))
		}

		got := selectorRepresentatives(names, []*regexp.Regexp{app})
		require.Len(t, got, 1, "%d names under one selector must collapse to one representative", n)
	}
}
