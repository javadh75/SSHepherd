package manifest

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCheckMappingKey pins checkMappingKey on its own: config.Parse already
// refuses most of these keys before Load walks the tree, so only a direct
// call shows that each check holds should that order change (G001).
func TestCheckMappingKey(t *testing.T) {
	tests := []struct {
		name string
		key  yaml.Node
		want string // "" = accepted
	}{
		{"plain key", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "users"}, ""},
		{"sequence as key", yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}, "unsupported mapping key"},
		{"null key", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "~"}, "unsupported mapping key"},
		{"empty key", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""}, "unsupported mapping key"},
		{"merge tag, other spelling", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!merge", Value: "m"}, "YAML merge key"},
		{"<< with a string tag", yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "<<"}, "YAML merge key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := tt.key
			k.Line = 7
			err := checkMappingKey(&k)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("checkMappingKey = %v, want nil", err)
				}
				return
			}
			var ue *UnsupportedError
			if !errors.As(err, &ue) || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "line 7") {
				t.Fatalf("checkMappingKey = %v, want an UnsupportedError containing %q at line 7", err, tt.want)
			}
		})
	}
}
