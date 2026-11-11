package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// unsafeText reports whether s holds an unsafe rune (authkeys.IsUnsafeRune)
// or is not valid UTF-8: IsUnsafeRune sees an invalid byte only as U+FFFD,
// but a raw 0x9B is CSI to a terminal in an 8-bit locale (review F008).
func unsafeText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, authkeys.IsUnsafeRune)
}

// invalidUTF8 reports every string field of the decoded manifest that is not
// valid UTF-8, by its YAML path (review F008). YAML text is UTF-8, so only a
// !!binary scalar can carry other bytes into a string field, and every
// string field is printed somewhere (reports, plans, errors). The message
// names the path, never the bytes.
func invalidUTF8(c *Config) error {
	var errs []error
	walkText(reflect.ValueOf(c).Elem(), "", func(path, s string) {
		if !utf8.ValidString(s) {
			errs = append(errs, fmt.Errorf("%s is not valid UTF-8 (manifest text must be; a !!binary scalar can hold other bytes)", path))
		}
	})
	return errors.Join(errs...)
}

// walkText calls visit for every string reachable from v through exported
// YAML fields and slices, with its YAML path ("users[0].keys[1]").
func walkText(v reflect.Value, path string, visit func(path, s string)) {
	switch v.Kind() {
	case reflect.String:
		visit(path, v.String())
	case reflect.Slice:
		for i := range v.Len() {
			walkText(v.Index(i), fmt.Sprintf("%s[%d]", path, i), visit)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if !f.IsExported() || name == "" || name == "-" {
				continue
			}
			if path != "" {
				name = path + "." + name
			}
			walkText(v.Field(i), name, visit)
		}
	}
}
