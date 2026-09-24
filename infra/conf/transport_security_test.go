package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestTLSConfigAllowsInsecureConnections(t *testing.T) {
	tests := []struct {
		name string
		json string
		want bool
	}{
		{"enabled", `{"security":"tls","tlsSettings":{"allowInsecure":true}}`, true},
		{"explicitly disabled", `{"security":"tls","tlsSettings":{"allowInsecure":false}}`, false},
		{"disabled by default", `{"security":"tls"}`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var streamConfig StreamConfig
			if err := json.Unmarshal([]byte(test.json), &streamConfig); err != nil {
				t.Fatal(err)
			}

			built, err := streamConfig.Build()
			if err != nil {
				t.Fatal(err)
			}
			instance, err := built.SecuritySettings[0].GetInstance()
			if err != nil {
				t.Fatal(err)
			}

			config := instance.(*tls.Config)
			field := config.ProtoReflect().Descriptor().Fields().ByName("allow_insecure")
			if field == nil || field.Number() != 1 {
				t.Fatal("allowInsecure is not protobuf field 1")
			}
			if config.GetAllowInsecure() != test.want {
				t.Fatalf("allowInsecure = %v, want %v", config.GetAllowInsecure(), test.want)
			}
			if config.GetTLSConfig().InsecureSkipVerify != test.want {
				t.Fatalf("InsecureSkipVerify = %v, want %v", config.GetTLSConfig().InsecureSkipVerify, test.want)
			}
		})
	}
}
