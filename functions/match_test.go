package functions_test

import (
	"testing"

	"github.com/funinthecloud/protosource-auth/functions"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		function string
		want     bool
	}{
		// Exact matches.
		{"exact match", "auth.user.v1.Create", "auth.user.v1.Create", true},
		{"exact non-match", "auth.user.v1.Create", "auth.user.v1.Lock", false},
		{"empty pattern empty function matches literally", "", "", true},
		{"empty pattern non-empty function", "", "auth.user.v1.Create", false},
		{"non-empty pattern empty function", "auth.user.v1.Create", "", false},

		// Super-admin.
		{"star matches anything", "*", "auth.user.v1.Create", true},
		{"star matches empty function", "*", "", true},
		{"star matches another package entirely", "*", "showcase.app.todolist.v1.Create", true},

		// Prefix wildcard.
		{"package wildcard matches command in package", "auth.user.v1.*", "auth.user.v1.Create", true},
		{"package wildcard matches different command in same package", "auth.user.v1.*", "auth.user.v1.Lock", true},
		{"package wildcard matches nested command", "auth.user.v1.*", "auth.user.v1.x.Nested", true},
		{"package wildcard does not match different package", "auth.user.v1.*", "auth.role.v1.Create", false},

		// Multi-segment prefix.
		{"broad wildcard matches any auth package", "auth.*", "auth.user.v1.Create", true},
		{"broad wildcard matches another auth package", "auth.*", "auth.role.v1.AddFunction", true},
		{"broad wildcard does not match unrelated package with same letters", "auth.*", "authentication.v1.Login", false},
		{"broad wildcard does not match completely unrelated package", "auth.*", "showcase.app.todolist.v1.Create", false},

		// Segment boundary enforcement: "auth.*" must not match "auth" alone.
		{"prefix wildcard does not match exact prefix without dot", "auth.*", "auth", false},
		{"prefix wildcard matches just the next character after the dot", "auth.*", "auth.x", true},

		// Literal wildcards that don't end with ".*" are treated as exact strings.
		{"leading wildcard is literal and never matches", "*.Create", "auth.user.v1.Create", false},
		{"in-middle wildcard is literal", "auth.*.Create", "auth.user.v1.Create", false},
		{"literal star-only segment is a literal pattern", "auth.*.v1", "auth.user.v1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := functions.Match(tc.pattern, tc.function)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.function, got, tc.want)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		function string
		want     bool
	}{
		{
			name:     "empty set never matches",
			patterns: nil,
			function: "auth.user.v1.Create",
			want:     false,
		},
		{
			name:     "single exact pattern matches",
			patterns: []string{"auth.user.v1.Create"},
			function: "auth.user.v1.Create",
			want:     true,
		},
		{
			name:     "single exact pattern misses",
			patterns: []string{"auth.user.v1.Create"},
			function: "auth.user.v1.Lock",
			want:     false,
		},
		{
			name:     "one wildcard in a mix grants access",
			patterns: []string{"auth.role.v1.Create", "auth.user.v1.*", "showcase.app.todolist.v1.Rename"},
			function: "auth.user.v1.Lock",
			want:     true,
		},
		{
			name:     "super-admin wildcard in mix grants everything",
			patterns: []string{"auth.user.v1.Create", "*"},
			function: "showcase.app.todolist.v1.Archive",
			want:     true,
		},
		{
			name:     "none of several specific patterns match",
			patterns: []string{"auth.user.v1.Create", "auth.user.v1.Lock", "auth.user.v1.Delete"},
			function: "auth.role.v1.Create",
			want:     false,
		},
		{
			name:     "stops at first match (behavioural, not observable here)",
			patterns: []string{"auth.user.v1.Create", "*"},
			function: "auth.user.v1.Create",
			want:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := functions.MatchAny(tc.patterns, tc.function)
			if got != tc.want {
				t.Errorf("MatchAny(%v, %q) = %v, want %v", tc.patterns, tc.function, got, tc.want)
			}
		})
	}
}
