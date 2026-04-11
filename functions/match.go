// Package functions provides wildcard matching for canonical function-name
// strings as stored on [Role] grants. The matcher is the trust boundary
// between a caller's granted function set and the specific function the
// authorizer is gating — it must be simple enough to reason about at a
// glance and exhaustively tested.
//
// Function names follow the convention "{proto_package}.{CommandMessageName}"
// (for example, "auth.user.v1.Create"). The supported wildcard forms are:
//
//   - "*" alone: matches every function name (super-admin grant).
//   - "prefix.*": matches any function name whose string begins with
//     "prefix." (the trailing "." is retained as a segment boundary so
//     "auth.*" does not accidentally match "authentication.v1.Login").
//   - anything else: literal exact match.
//
// Leading and in-middle wildcards are intentionally unsupported to keep
// grants easy to audit and prevent surprising overgrants. A pattern like
// "*.Create" is treated as a literal string and will never match a real
// function name.
package functions

import "strings"

// Match reports whether function is permitted by pattern. See the package
// docs for the supported wildcard syntax.
func Match(pattern, function string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		// Keep the trailing "." — "auth." is a segment boundary so
		// "authentication..." cannot sneak through.
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(function, prefix)
	}
	return pattern == function
}

// MatchAny reports whether function is permitted by any pattern in
// patterns. Returns false if patterns is empty.
func MatchAny(patterns []string, function string) bool {
	for _, p := range patterns {
		if Match(p, function) {
			return true
		}
	}
	return false
}
