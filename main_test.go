package main

import (
	"reflect"
	"testing"
)

func TestFilterEvidence(t *testing.T) {
	tests := []struct {
		name      string
		details   []EvidenceDetail
		targetEnv string
		want      []EvidenceDetail
	}{
		{
			name: "Match in Rule",
			details: []EvidenceDetail{
				{Rule: "Linux Malware", Criticality: 3, EvidenceString: "Found hash"},
				{Rule: "Windows Malware", Criticality: 2, EvidenceString: "Found registry key"},
			},
			targetEnv: "linux",
			want: []EvidenceDetail{
				{Rule: "Linux Malware", Criticality: 3, EvidenceString: "Found hash"},
			},
		},
		{
			name: "Match in EvidenceString",
			details: []EvidenceDetail{
				{Rule: "Generic Malware", Criticality: 3, EvidenceString: "Affects AWS environments"},
				{Rule: "Generic Malware", Criticality: 2, EvidenceString: "Affects Azure environments"},
			},
			targetEnv: "AWS",
			want: []EvidenceDetail{
				{Rule: "Generic Malware", Criticality: 3, EvidenceString: "Affects AWS environments"},
			},
		},
		{
			name: "Case Insensitive Match",
			details: []EvidenceDetail{
				{Rule: "Mac OS X attack", Criticality: 4, EvidenceString: "xyz"},
			},
			targetEnv: "mac",
			want: []EvidenceDetail{
				{Rule: "Mac OS X attack", Criticality: 4, EvidenceString: "xyz"},
			},
		},
		{
			name: "No Match",
			details: []EvidenceDetail{
				{Rule: "Windows Malware", Criticality: 3, EvidenceString: "Found registry key"},
			},
			targetEnv: "Linux",
			want:      nil,
		},
		{
			name:      "Empty Details",
			details:   []EvidenceDetail{},
			targetEnv: "Linux",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterEvidence(tt.details, tt.targetEnv)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterEvidence() = %v, want %v", got, tt.want)
			}
		})
	}
}
