package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

// yamlStrings are scalars whose YAML form depends on quoting rules, block
// styles and type resolution.
var yamlStrings = []string{
	"", "plain", "two words", "null", "Null", "~", "true", "yes", "No", "on", "10", "-3", "1e3", "0x1F", "1_000",
	".inf", "2001-12-14", "#/components/schemas/X", "a: b", "a #b", "- x", "? x", "{x}", "[x]", "*alias", "&anchor",
	"!tag", "|pipe", ">gt", "@at", "`tick", "%pct", "'single'", "\"double\"", "trailing ", " leading", "tab\there",
	"line\nbreak", "line\nbreak\n", "keep\n\n", " lead\nline", "trail \nline", "é unicode ✓", "\u0007bell", "a\r\nb",
	"/items/{id}", "x:y", "x: ", "text with: colon", "ends:", "-", "--- doc", "...", "a\u2028b", "\ufeffbom",
	// Long enough for go-yaml to fold at column 80, depending on where they start.
	"The account that owns this contact. It is non-null only for a current member of the tenant, and removal clears it.",
	"Short words a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h i j k l m n o p q r s t u v w x y z.",
	"Quoted: because of the colon, this long description must be single quoted when go-yaml writes it out, and folded.",
	"#Hash first, then a long tail of words that keeps going well past the eighty column limit of the emitter's width.",
	"Tab\tinside a long text forces double quotes, and the long text then folds with escapes past the width of eighty.",
	"Line one of a long literal block that runs past the width without folding, as literal blocks never fold at all.\nLine two.",
	"Unbroken-long-token-without-any-spaces-that-cannot-fold-anywhere-even-past-the-eighty-column-limit-of-go-yaml",
	"Trailing spaces after a long sentence that is longer than eighty characters force double quotes in the end   ",
	"Two  spaces  between  words  in  a  long  sentence  that  folds  past  the  width,  which  go-yaml  keeps  as  is",
}

var yamlKeys = []string{"a", "b", "B", "_x", "a2", "a10", "a02", "10", "9", "x9y", "x10y", "é", "z z", "#k", "null", "", "200", "default", "$ref"}

func randomJSON(random *rand.Rand, depth int) any {
	switch n := random.Intn(10); {
	case depth > 0 && n < 3:
		object := map[string]any{}
		for range random.Intn(5) {
			object[yamlKeys[random.Intn(len(yamlKeys))]] = randomJSON(random, depth-1)
		}
		return object
	case depth > 0 && n < 5:
		array := []any{}
		for range random.Intn(4) {
			array = append(array, randomJSON(random, depth-1))
		}
		return array
	case n < 7:
		return yamlStrings[random.Intn(len(yamlStrings))]
	case n == 7:
		return []any{0.0, -0.0, 1.0, 200.0, 1e6, 1e21, 0.5, 1e-7, 123456789.0, -42.0, 3.14159}[random.Intn(11)]
	case n == 8:
		return random.Intn(2) == 0
	default:
		return nil
	}
}

func assertSameYAML(t *testing.T, label string, raw []byte) {
	t.Helper()
	want, err := yaml.JSONToYAML(raw)
	if err != nil {
		t.Fatalf("%s: JSONToYAML: %v", label, err)
	}
	got, err := jsonToYAML(raw)
	if errors.Is(err, errComplexKey) {
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s: output differs\njson: %s\ngot:\n%s\nwant:\n%s", label, raw, got, want)
	}
	// And it reads back as the same JSON.
	back, err := yaml.YAMLToJSON(got)
	if err != nil {
		t.Fatalf("%s: YAMLToJSON: %v", label, err)
	}
	var a, b any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(back, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s: round trip changed the document\njson: %s\nback: %s", label, raw, back)
	}
}

func TestJSONToYAMLMatchesGoYAML(t *testing.T) {
	random := rand.New(rand.NewSource(7))
	for i := range 3000 {
		document := map[string]any{"root": randomJSON(random, 5)}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		assertSameYAML(t, fmt.Sprintf("document %d", i), raw)
	}
	for _, value := range yamlStrings {
		raw, _ := json.Marshal(map[string]any{"value": value, "list": []any{value, []any{value}}, "nested": map[string]any{"k": value}})
		assertSameYAML(t, fmt.Sprintf("%q", value), raw)
	}
	// The composed documents of the fixture contracts.
	bindings, err := loadBindings(filepath.Join("testdata", "bindings.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	registrations, err := loadLocal(filepath.Join("testdata", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compileStrict(registrations, bindings)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.YAMLToJSON(compiled.specYAML)
	if err != nil {
		t.Fatal(err)
	}
	assertSameYAML(t, "fixtures", raw)
	// Optionally a composed document from elsewhere, such as the live one.
	if path := os.Getenv("DARBAN_YAML_JSON"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		assertSameYAML(t, path, raw)
	}
}

func TestJSONToYAMLLeavesComplexKeysToGoYAML(t *testing.T) {
	for _, key := range []string{"multi\nline", "line\n"} {
		raw, _ := json.Marshal(map[string]any{key: 1})
		if _, err := jsonToYAML(raw); !errors.Is(err, errComplexKey) {
			t.Errorf("%q: %v", key, err)
		}
	}
}
