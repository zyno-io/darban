package main

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// documentTags collects the published tags of the documented operations, by
// service, for the document's tags and x-tagGroups. Tag names stay as
// published, since SDK generators use them; only their display names are
// made readable.
type documentTags map[string]map[string]documentTag

type documentTag struct {
	original, description string
}

func (t documentTags) add(service string, tag publishedTag, description string) {
	if t[service] == nil {
		t[service] = make(map[string]documentTag)
	}
	if existing, ok := t[service][tag.name]; ok && existing.description != "" {
		return
	}
	t[service][tag.name] = documentTag{tag.original, description}
}

// render returns the top-level tags, grouped by service in name order and
// sorted by name within a group, and the x-tagGroups that name each group by
// its service title. A tag that more than one service publishes, which
// prefixTags: firstOnly allows, is listed once and appears in each group.
func (t documentTags) render(title func(service string) string) ([]map[string]any, []map[string]any) {
	var tags, groups []map[string]any
	entries, named := make(map[string]map[string]any), make(map[string]bool)
	for _, service := range slices.Sorted(maps.Keys(t)) {
		names := slices.Sorted(maps.Keys(t[service]))
		for _, name := range names {
			if entries[name] != nil {
				continue
			}
			tag := t[service][name]
			entry := map[string]any{"name": name, "x-displayName": displayName(tag.original)}
			if tag.description != "" {
				entry["description"] = tag.description
			}
			entries[name] = entry
			tags = append(tags, entry)
		}
		// Two tags of a group can read the same, as admin and shopAdmin do
		// with prefixTags: firstOnly; the later one shows its published name.
		shown := make(map[string]bool, len(names))
		for _, name := range names {
			entry := entries[name]
			if shown[entry["x-displayName"].(string)] {
				entry["x-displayName"] = name
			}
			shown[entry["x-displayName"].(string)] = true
		}
		group := title(service)
		if group == "" {
			group = titleCase(service)
		}
		// Two services with one title, as a title and another service's
		// default can be, still get distinct groups.
		if named[group] {
			group += " (" + service + ")"
		}
		named[group] = true
		groups = append(groups, map[string]any{"name": group, "tags": names})
	}
	return tags, groups
}

// displayName makes a contract's tag name readable: it splits it into words
// at dots, dashes, underscores, spaces and case changes, and capitalizes each
// word, so salesBillingCatalog becomes "Sales Billing Catalog" and
// crm.authPolicies "Crm Auth Policies". An acronym stays one word:
// XCrmMemberships becomes "X Crm Memberships" and SSEEvents "SSE Events".
func displayName(tag string) string {
	var words []string
	var word []rune
	flush := func() {
		if len(word) > 0 {
			words = append(words, string(word))
			word = nil
		}
	}
	runes := []rune(tag)
	for i, r := range runes {
		switch {
		case r == '.' || r == '-' || r == '_' || unicode.IsSpace(r):
			flush()
			continue
		case unicode.IsUpper(r) && len(word) > 0:
			previous := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextLower {
				flush()
			}
		}
		word = append(word, r)
	}
	flush()
	if len(words) == 0 {
		return tag
	}
	for i, w := range words {
		words[i] = uppercaseFirst(w)
	}
	return strings.Join(words, " ")
}

// titleCase turns a service name such as book-catalog into "Book Catalog".
func titleCase(service string) string {
	parts := strings.Split(service, "-")
	for i, part := range parts {
		parts[i] = uppercaseFirst(part)
	}
	return strings.Join(parts, " ")
}

// mergeSecuritySchemes publishes each security scheme that every service
// defines identically once, under its original name: auth.accountBearer and
// suite.accountBearer become accountBearer when their definitions are equal,
// and the operations' security requirements name it. A scheme whose
// definitions differ between services keeps its prefixed names. Nothing else
// refers to a scheme: a contract cannot $ref one.
func mergeSecuritySchemes(components map[string]map[string]any, paths map[string]map[string]any) {
	schemes := components["securitySchemes"]
	byOriginal := make(map[string][]string)
	for _, prefixed := range slices.Sorted(maps.Keys(schemes)) {
		// Every key is <service>.<name>, and a service name has no dot.
		if _, original, ok := strings.Cut(prefixed, "."); ok {
			byOriginal[original] = append(byOriginal[original], prefixed)
		}
	}
	renamed := make(map[string]string)
	for _, original := range slices.Sorted(maps.Keys(byOriginal)) {
		names := byOriginal[original]
		// A dotted name can equal another service's prefixed one, such as
		// sales.bearer for auth's scheme sales.bearer; keep both prefixed.
		if _, taken := schemes[original]; taken {
			continue
		}
		first, err := json.Marshal(schemes[names[0]])
		if err != nil {
			continue
		}
		identical := true
		for _, name := range names[1:] {
			if other, err := json.Marshal(schemes[name]); err != nil || string(other) != string(first) {
				identical = false
				break
			}
		}
		if identical {
			for _, name := range names {
				renamed[name] = original
			}
		}
	}
	if len(renamed) == 0 {
		return
	}
	for name, original := range renamed {
		definition := schemes[name]
		delete(schemes, name)
		schemes[original] = definition
	}
	for _, item := range paths {
		for _, value := range item {
			operation, ok := value.(map[string]any)
			if !ok {
				continue
			}
			security, ok := operation["security"].(securityRequirements)
			if !ok {
				continue
			}
			for i, requirement := range security {
				next := make(map[string][]string, len(requirement))
				for name, scopes := range requirement {
					if original, ok := renamed[name]; ok {
						name = original
					}
					next[name] = scopes
				}
				security[i] = next
			}
		}
	}
}
