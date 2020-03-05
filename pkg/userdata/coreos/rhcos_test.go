package coreos

import (
	"encoding/json"
	"testing"
)

func TestGenerateIgnitionForRole(t *testing.T) {
	type args struct {
		config      *RenderConfig
		role        string
		templateDir string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Whao",
			args: args{
				config: &RenderConfig{
					Platform: "vsphere",
				},
				role:        "worker",
				templateDir: "templates",
			},
			want:    "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateIgnitionForRole(tt.args.config, defaultSSHConfig([]string{"ssh-rsa AAAAB3Nza..."}), tt.args.role, tt.args.templateDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateIgnitionForRole() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			m, err := json.Marshal(got)
			if err != nil {
				t.Errorf("Error marshaling ignition configuration: %v", m)
			}
			if string(m) != tt.want {
				t.Errorf("GenerateIgnitionForRole() = %v, want %v", string(m), tt.want)
			}
		})
	}
}
