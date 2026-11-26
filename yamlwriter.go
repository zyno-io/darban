package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	yaml2 "go.yaml.in/yaml/v2"
)

// jsonToYAML writes a JSON document as block YAML without building the
// document as a tree. It walks the JSON bytes in place and has go-yaml v2
// format each scalar and key, so quoting, block scalars, folding and complex
// keys match what go-yaml writes for the same document, as
// sigs.k8s.io/yaml.JSONToYAML does. Keys are sorted as go-yaml sorts them.
//
// Unlike JSONToYAML it never parses the JSON as YAML, so it accepts every
// JSON document: a key of any length, and characters go-yaml's reader
// refuses, such as DEL, C1 controls and U+FFFE, which go-yaml's writer
// escapes. U+0085 is written as \N, where JSONToYAML read it as a space.
func jsonToYAML(raw []byte) ([]byte, error) {
	w := yamlWriter{out: bytes.NewBuffer(make([]byte, 0, len(raw))), values: map[string]string{}, keys: map[string]string{}}
	value := bytes.TrimSpace(raw)
	switch {
	case len(value) == 0:
		return nil, errors.New("empty JSON document")
	case value[0] == '{' && !emptyComposite(value):
		if err := w.mapping(value, 0, false); err != nil {
			return nil, err
		}
	case value[0] == '[' && !emptyComposite(value):
		if err := w.sequence(value, 0, false); err != nil {
			return nil, err
		}
	default:
		text, err := w.scalar(value, 0)
		if err != nil {
			return nil, err
		}
		w.out.WriteString(text)
		if last, _ := utf8.DecodeLastRuneInString(text); !strings.ContainsRune(yamlBreaks, last) {
			w.out.WriteByte('\n')
		}
	}
	return w.out.Bytes(), nil
}

type yamlWriter struct {
	out *bytes.Buffer
	// values and keys cache the go-yaml text of each distinct string.
	values, keys map[string]string
	// frames is the path to the value being written: a mapping key, or a
	// sequence item when seq is set.
	frames []yamlFrame
}

type yamlFrame struct {
	key string
	seq bool
}

// yamlWidth is the column past which go-yaml folds a scalar at a space.
const yamlWidth = 80

func (w *yamlWriter) pad(column int) {
	for range column {
		w.out.WriteByte(' ')
	}
}

// mapping writes a JSON object whose keys start at column. inline means the
// first key goes on the current line, after a sequence item's "- ".
func (w *yamlWriter) mapping(object []byte, column int, inline bool) error {
	entries, err := objectEntries(object)
	if err != nil {
		return err
	}
	for i, entry := range entries {
		if i > 0 || !inline {
			w.pad(column)
		}
		key, simple, err := w.key(entry.key)
		if err != nil {
			return err
		}
		if !simple {
			// A complex key: "? key", then ": value" with the value inline,
			// like a sequence item's.
			if key, err = w.complexKey(entry.key, column); err != nil {
				return err
			}
			w.out.WriteString("? " + key)
			w.pad(column)
			w.out.WriteByte(':')
			w.frames = append(w.frames, yamlFrame{key: entry.key})
			err = w.member(entry.value, column, column+2, true)
		} else {
			w.out.WriteString(key)
			w.out.WriteByte(':')
			w.frames = append(w.frames, yamlFrame{key: entry.key})
			err = w.member(entry.value, column, column+utf8.RuneCountInString(key)+2, false)
		}
		w.frames = w.frames[:len(w.frames)-1]
		if err != nil {
			return err
		}
	}
	return nil
}

// sequence writes a JSON array whose items start at column.
func (w *yamlWriter) sequence(array []byte, column int, inline bool) error {
	items, err := arrayItems(array)
	if err != nil {
		return err
	}
	for i, item := range items {
		if i > 0 || !inline {
			w.pad(column)
		}
		w.out.WriteString("-")
		w.frames = append(w.frames, yamlFrame{seq: true})
		err := w.member(item, column, column+2, true)
		w.frames = w.frames[:len(w.frames)-1]
		if err != nil {
			return err
		}
	}
	return nil
}

// member writes the value of a mapping entry or a sequence item at column,
// after its "key:" or "-". A nested collection is indented two more, and a
// sequence item's starts on the item's line. A mapping entry's sequence is
// not indented: go-yaml writes indentless sequences in mappings. A scalar
// starts at start.
func (w *yamlWriter) member(value []byte, column, start int, item bool) error {
	nested := column + 2
	switch {
	case value[0] == '{' && emptyComposite(value):
		w.out.WriteString(" {}\n")
	case value[0] == '[' && emptyComposite(value):
		w.out.WriteString(" []\n")
	case value[0] == '{' && item:
		w.out.WriteByte(' ')
		return w.mapping(value, nested, true)
	case value[0] == '[' && item:
		w.out.WriteByte(' ')
		return w.sequence(value, nested, true)
	case value[0] == '{':
		w.out.WriteByte('\n')
		return w.mapping(value, nested, false)
	case value[0] == '[':
		w.out.WriteByte('\n')
		return w.sequence(value, column, false)
	default:
		text, err := w.scalar(value, start)
		if err != nil {
			return err
		}
		w.out.WriteString(" " + text)
		// A scalar formatted in context ends its own line, with a line feed
		// or with a block scalar's last Unicode line break.
		if last, _ := utf8.DecodeLastRuneInString(text); !strings.ContainsRune(yamlBreaks, last) {
			w.out.WriteByte('\n')
		}
	}
	return nil
}

// scalar formats a JSON scalar that starts at column as go-yaml writes it
// after JSONToYAML parses it.
func (w *yamlWriter) scalar(value []byte, column int) (string, error) {
	switch value[0] {
	case '"':
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return "", err
		}
		formatted, cached := w.values[text]
		if !cached {
			out, err := yaml2.Marshal(map[string]string{"k": text})
			if err != nil {
				return "", err
			}
			formatted = strings.TrimSuffix(strings.TrimPrefix(string(out), "k: "), "\n")
			w.values[text] = formatted
		}
		// A one-line scalar that ends within the width cannot fold, wherever
		// it starts. Any other is written in its own context: go-yaml folds
		// at a column and indents continuation lines by the nesting.
		if strings.ContainsAny(formatted, yamlBreaks) || column+utf8.RuneCountInString(formatted) > yamlWidth {
			return w.inContext(text)
		}
		return formatted, nil
	case 't', 'f', 'n':
		return string(value), nil
	default:
		return yamlNumber(string(value))
	}
}

// yamlBreaks are the characters YAML reads as line breaks.
const yamlBreaks = "\n\u0085\u2028\u2029"

// chain wraps a value in a document with only the current path.
func (w *yamlWriter) chain(leaf any) any {
	value := leaf
	for i := len(w.frames) - 1; i >= 0; i-- {
		if w.frames[i].seq {
			value = []any{value}
		} else {
			value = map[string]any{w.frames[i].key: value}
		}
	}
	return value
}

// inContext formats a string at the current path by having go-yaml write a
// document with only that path, then taking what follows the path's header.
func (w *yamlWriter) inContext(text string) (string, error) {
	chain := w.chain
	header, err := yaml2.Marshal(chain("x"))
	if err != nil {
		return "", err
	}
	out, err := yaml2.Marshal(chain(text))
	if err != nil {
		return "", err
	}
	prefix := len(header) - len("x\n")
	if !bytes.Equal(out[:prefix], header[:prefix]) {
		return "", errors.New("unexpected YAML context")
	}
	return string(out[prefix:]), nil
}

// yamlNumber formats a JSON number as go-yaml resolves and writes it: an
// integer as an integer, anything else as a shortest float.
func yamlNumber(text string) (string, error) {
	if i, err := strconv.ParseInt(text, 0, 64); err == nil {
		return strconv.FormatInt(i, 10), nil
	}
	if u, err := strconv.ParseUint(text, 0, 64); err == nil {
		return strconv.FormatUint(u, 10), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return "", fmt.Errorf("invalid JSON number %q", text)
	}
	return strconv.FormatFloat(f, 'g', -1, 64), nil
}

// key formats a simple key, which does not depend on where it is. simple is
// false for a key go-yaml writes as a complex key.
func (w *yamlWriter) key(key string) (string, bool, error) {
	if formatted, cached := w.keys[key]; cached {
		return formatted, formatted != "", nil
	}
	out, err := yaml2.Marshal(map[string]int{key: 0})
	if err != nil {
		return "", false, err
	}
	formatted, simple := strings.CutSuffix(string(out), ": 0\n")
	if !simple || strings.Contains(formatted, "\n") || strings.HasPrefix(formatted, "? ") {
		formatted = ""
	}
	w.keys[key] = formatted
	return formatted, formatted != "", nil
}

// complexKey formats a complex key at the current path, where go-yaml may
// fold it, by having go-yaml write a document with only that path and key. The
// text ends with its line break.
func (w *yamlWriter) complexKey(key string, column int) (string, error) {
	header, err := yaml2.Marshal(w.chain(map[string]any{"k": "x"}))
	if err != nil {
		return "", err
	}
	out, err := yaml2.Marshal(w.chain(map[string]any{key: "x"}))
	if err != nil {
		return "", err
	}
	prefix := len(header) - len("k: x\n")
	rest, ok := bytes.CutPrefix(out[prefix:], []byte("? "))
	if !ok || !bytes.Equal(out[:prefix], header[:prefix]) {
		return "", errors.New("unexpected YAML context")
	}
	text, ok := bytes.CutSuffix(rest, []byte(strings.Repeat(" ", column)+": x\n"))
	if !ok {
		return "", errors.New("unexpected YAML complex key")
	}
	return string(text), nil
}

type jsonEntry struct {
	key   string
	value []byte
}

// objectEntries splits a JSON object into its members, sorted as go-yaml v2
// sorts string keys.
func objectEntries(object []byte) ([]jsonEntry, error) {
	var entries []jsonEntry
	rest := bytes.TrimSpace(object[1:])
	for len(rest) > 0 && rest[0] != '}' {
		end, err := jsonValueEnd(rest)
		if err != nil {
			return nil, err
		}
		var key string
		if err := json.Unmarshal(rest[:end], &key); err != nil {
			return nil, err
		}
		rest = bytes.TrimSpace(rest[end:])
		if len(rest) == 0 || rest[0] != ':' {
			return nil, errors.New("invalid JSON object")
		}
		rest = bytes.TrimSpace(rest[1:])
		end, err = jsonValueEnd(rest)
		if err != nil {
			return nil, err
		}
		entries = append(entries, jsonEntry{key, rest[:end]})
		rest = bytes.TrimSpace(rest[end:])
		if len(rest) > 0 && rest[0] == ',' {
			rest = bytes.TrimSpace(rest[1:])
		}
	}
	slices.SortStableFunc(entries, func(a, b jsonEntry) int {
		switch {
		case yamlKeyLess(a.key, b.key):
			return -1
		case yamlKeyLess(b.key, a.key):
			return 1
		}
		return 0
	})
	return entries, nil
}

func arrayItems(array []byte) ([][]byte, error) {
	var items [][]byte
	rest := bytes.TrimSpace(array[1:])
	for len(rest) > 0 && rest[0] != ']' {
		end, err := jsonValueEnd(rest)
		if err != nil {
			return nil, err
		}
		items = append(items, rest[:end])
		rest = bytes.TrimSpace(rest[end:])
		if len(rest) > 0 && rest[0] == ',' {
			rest = bytes.TrimSpace(rest[1:])
		}
	}
	return items, nil
}

func emptyComposite(value []byte) bool {
	return len(bytes.TrimSpace(value[1:len(value)-1])) == 0
}

// jsonValueEnd returns the length of the JSON value that data starts with.
// The input is json.Marshal output, so it only needs to find the end.
func jsonValueEnd(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("unexpected end of JSON")
	}
	switch data[0] {
	case '"':
		for i := 1; i < len(data); i++ {
			switch data[i] {
			case '\\':
				i++
			case '"':
				return i + 1, nil
			}
		}
		return 0, errors.New("unterminated JSON string")
	case '{', '[':
		depth := 0
		for i := 0; i < len(data); i++ {
			switch data[i] {
			case '"':
				end, err := jsonValueEnd(data[i:])
				if err != nil {
					return 0, err
				}
				i += end - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, nil
				}
			}
		}
		return 0, errors.New("unterminated JSON value")
	default:
		i := 0
		for i < len(data) && !strings.ContainsRune(",}] \t\r\n", rune(data[i])) {
			i++
		}
		return i, nil
	}
}

// yamlKeyLess orders string keys as go-yaml v2's keyList does: letters sort
// before other characters, and runs of digits compare as numbers.
func yamlKeyLess(a, b string) bool {
	ar, br := []rune(a), []rune(b)
	for i := 0; i < len(ar) && i < len(br); i++ {
		if ar[i] == br[i] {
			continue
		}
		al := unicode.IsLetter(ar[i])
		bl := unicode.IsLetter(br[i])
		if al && bl {
			return ar[i] < br[i]
		}
		if al || bl {
			return bl
		}
		var ai, bi int
		var an, bn int64
		if ar[i] == '0' || br[i] == '0' {
			for j := i - 1; j >= 0 && unicode.IsDigit(ar[j]); j-- {
				if ar[j] != '0' {
					an = 1
					bn = 1
					break
				}
			}
		}
		for ai = i; ai < len(ar) && unicode.IsDigit(ar[ai]); ai++ {
			an = an*10 + int64(ar[ai]-'0')
		}
		for bi = i; bi < len(br) && unicode.IsDigit(br[bi]); bi++ {
			bn = bn*10 + int64(br[bi]-'0')
		}
		if an != bn {
			return an < bn
		}
		if ai != bi {
			return ai < bi
		}
		return ar[i] < br[i]
	}
	return len(ar) < len(br)
}
