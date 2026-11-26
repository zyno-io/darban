package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
	// Unicode line breaks at the end of a block scalar, and characters
	// go-yaml's reader refuses but its writer escapes.
	"a\nb\u2028", "a\nb\u2029", "a\nb\u2028\n", "next\u0085line", "del\u007f", "c1\u0080\u009f", "nonchar\ufffe\uffff",
}

var yamlKeys = []string{"a", "b", "B", "_x", "a2", "a10", "a02", "10", "9", "x9y", "x10y", "é", "z z", "#k", "null", "", "200", "default", "$ref",
	// Complex keys: a line break, over 128 bytes, folding, over 1024 bytes.
	"multi\nline", "keep\n\n", "sep\u2028", strings.Repeat("k", 130), strings.Repeat("word ", 40) + "end", strings.Repeat("x", 1100),
	"del\u007f" + strings.Repeat("y", 130)}

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

// assertSameYAML checks that jsonToYAML writes what JSONToYAML writes, except
// where JSONToYAML cannot read the JSON as YAML (a key over 1024 characters,
// DEL, C1 controls, U+FFFE) or reads U+0085 as a space, and that the output
// always reads back as the same JSON.
func assertSameYAML(t *testing.T, label string, raw []byte) {
	t.Helper()
	got, err := jsonToYAML(raw)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if want, err := yaml.JSONToYAML(raw); err == nil && !strings.ContainsRune(string(raw), '\u0085') && string(got) != string(want) {
		t.Fatalf("%s: output differs\njson: %s\ngot:\n%q\nwant:\n%q", label, raw, got, want)
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

func TestJSONToYAMLWritesWhatGoYAMLReadsBack(t *testing.T) {
	// Escapes for what go-yaml's reader refuses, and U+0085 kept as \N.
	raw, _ := json.Marshal(map[string]any{"a": "del\u007f", "b": "next\u0085line", "c": "c1\u0080", "d": "\ufffe"})
	got, err := jsonToYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "a: \"del\\x7F\"\nb: \"next\\Nline\"\nc: \"c1\\x80\"\nd: \"\\uFFFE\"\n"
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := yaml.JSONToYAML(raw); err == nil {
		t.Fatal("JSONToYAML now reads these; the documented difference is gone")
	}
	// A key too long for JSONToYAML is a complex key.
	long := strings.Repeat("k", 1100)
	raw, _ = json.Marshal(map[string]any{long: map[string]any{"a": 1}, "z": []any{1}})
	got, err = jsonToYAML(raw)
	if err != nil || !strings.HasPrefix(string(got), "? "+long+"\n: a: 1\n") {
		t.Fatalf("got %q, %v", got, err)
	}
	assertSameYAML(t, "long key", raw)
}

func extensionContract(operationID, extension string) string {
	return "openapi: 3.1.0\npaths:\n  /items:\n    get:\n      operationId: " + operationID +
		"\n      security: []\n      x-darban-policy: anonymous\n" + extension + "      responses: {'200': {description: OK}}\n"
}

func TestDocumentsJSONToYAMLCannotReadStillRender(t *testing.T) {
	// Base rendered with JSONToYAML, which cannot read these back, so the
	// contracts were rejected; with the render-free trials both alpha and
	// beta then went unserved.
	bindings := isolationBindings("alpha", "beta")
	beta := registration{serviceName: "beta", rewrites: "[]", openAPI: extensionContract("listBeta", "")}
	for name, extension := range map[string]string{
		"key over 1024":    "      x-big:\n        ? " + strings.Repeat("k", 1100) + "\n        : 1\n",
		"long key and DEL": "      x-big:\n        " + strings.Repeat("k", 130) + ": 1\n      x-note: \"a\\x7fb\"\n",
	} {
		alpha := registration{serviceName: "alpha", rewrites: "[]", openAPI: extensionContract("listAlpha", extension)}
		got, report := compile([]registration{alpha, beta}, bindings, nil)
		for _, service := range []string{"alpha", "beta"} {
			if outcome := report.services[service]; outcome.serving != servingCurrent || outcome.rejection != "" {
				t.Errorf("%s: %s = %+v", name, service, outcome)
			}
		}
		wantPaths(t, got, "/alpha/items", "/beta/items")
		if _, err := yaml.YAMLToJSON(got.specYAML); err != nil {
			t.Errorf("%s: the document does not read back: %v", name, err)
		}
	}
}

func TestRenderFailureIsBlamedOnTheContractThatCausesIt(t *testing.T) {
	render := renderYAML
	t.Cleanup(func() { renderYAML = render })
	renderYAML = func(raw []byte) ([]byte, error) {
		if strings.Contains(string(raw), "poison") {
			return nil, fmt.Errorf("cannot render")
		}
		return render(raw)
	}
	bindings := isolationBindings("alpha", "beta")
	alpha := registration{serviceName: "alpha", rewrites: "[]", openAPI: extensionContract("listAlpha", "      x-note: poison\n")}
	beta := registration{serviceName: "beta", rewrites: "[]", openAPI: extensionContract("listBeta", "")}
	check := func(label string, report compileReport, got candidate) {
		t.Helper()
		if outcome := report.services["alpha"]; outcome.serving == servingCurrent || !strings.Contains(outcome.rejection, "cannot render") {
			t.Errorf("%s: alpha = %+v", label, outcome)
		}
		if outcome := report.services["beta"]; outcome.serving != servingCurrent || outcome.rejection != "" {
			t.Errorf("%s: beta = %+v", label, outcome)
		}
		if !slices.Contains(routePaths(got), "/beta/items") || slices.Contains(routePaths(got), "/alpha/items") {
			t.Errorf("%s: routes %v", label, routePaths(got))
		}
	}
	for _, order := range [][]registration{{alpha, beta}, {beta, alpha}} {
		got, report := compile(order, bindings, nil)
		check("fresh", report, got)
	}
	good := registration{serviceName: "alpha", rewrites: "[]", openAPI: extensionContract("listAlpha", "")}
	_, r1 := compile([]registration{good, beta}, bindings, nil)
	got, r2 := compile([]registration{alpha, beta}, bindings, r1.accepted)
	if r2.services["alpha"].serving != servingLastGood || r2.services["beta"].serving != servingCurrent {
		t.Errorf("established: %+v %+v", r2.services["alpha"], r2.services["beta"])
	}
	wantPaths(t, got, "/alpha/items", "/beta/items")
}

func TestSecurityRequirementsKeepTheirSchemesTogether(t *testing.T) {
	contract := `openapi: 3.1.0
paths:
  /items:
    get:
      operationId: listItems
      security: [{c: [], a: [], b: []}, {d: []}]
      responses: {'200': {description: OK}}
components:
  securitySchemes:
    a: {type: http, scheme: bearer}
    b: {type: apiKey, in: header, name: X-B}
    c: {type: apiKey, in: header, name: X-C}
    d: {type: http, scheme: basic}
`
	reg := registration{serviceName: "zoo", rewrites: "[]", openAPI: contract}
	first, _ := compile([]registration{reg}, isolationBindings("zoo"), nil)
	for range 30 {
		again, _ := compile([]registration{reg}, isolationBindings("zoo"), nil)
		if again.revision != first.revision || string(again.specYAML) != string(first.specYAML) {
			t.Fatal("the document depends on map order")
		}
	}
	var document struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if err := yaml.Unmarshal(first.specYAML, &document); err != nil {
		t.Fatal(err)
	}
	security := document.Paths["/zoo/items"]["get"].Security
	if len(security) != 2 || len(security[0]) != 3 || len(security[1]) != 1 || security[1]["zoo.d"] == nil {
		t.Fatalf("security %v", security)
	}
}

func TestJSONToYAMLTopLevelScalars(t *testing.T) {
	for _, value := range yamlStrings {
		raw, _ := json.Marshal(value)
		assertSameYAML(t, fmt.Sprintf("top-level %q", value), raw)
	}
}
