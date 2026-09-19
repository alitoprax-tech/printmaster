package main

import "testing"

func TestIsKyoceraModelScript(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "/js/jssrc/model/wlm/index.model.htm", want: true},
		{path: "/js/jssrc/model/startwlm/Device_Config.model.htm", want: true},
		{path: "/js/jssrc/view_model/startwlm/Start_Wlm.viewmodel.js", want: false},
		{path: "/startwlm/Start_Wlm.htm", want: false},
		{path: "/js/jssrc/model/wlm/index.htm", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isKyoceraModelScript(tt.path); got != tt.want {
				t.Fatalf("isKyoceraModelScript(%q) = %t, want %t", tt.path, got, tt.want)
			}
		})
	}
}
