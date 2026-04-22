package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestLiveAPI fetches real data from Recorded Future.
// It requires the RF_API_TOKEN environment variable to be set.
func TestLiveAPI(t *testing.T) {
	apiToken := os.Getenv("RF_API_TOKEN")
	if apiToken == "" {
		t.Skip("Skipping live API test: RF_API_TOKEN is not set.")
	}

	ipToTest := "185.220.101.14"
	targetEnv := "" // Empty string matches all evidence so we can see what comes back

	t.Logf("Fetching Recorded Future data for IP: %s", ipToTest)

	rfData, err := fetchRecordedFutureData(ipToTest, apiToken)
	if err != nil {
		t.Fatalf("Failed to fetch data: %v", err)
	}

	// Diagnostic: Print the whole struct to see if anything is there
	fmt.Printf("\n--- Full Decoded Response ---\n%+v\n", rfData)

	verdict := getVerdict(rfData.Data.Risk.Score)
	fmt.Printf("\n--- SOC Analyst Summary ---\n")
	fmt.Printf("IP Address: %s\n", ipToTest)
	fmt.Printf("Verdict: %s (Score: %d, Level: %d)\n", verdict, rfData.Data.Risk.Score, rfData.Data.Risk.Level)
	fmt.Printf("IntelCard: %s\n", rfData.Data.IntelCard)
	fmt.Printf("Location: %+v\n", rfData.Data.Location)
	fmt.Printf("Threat Lists: %+v\n", rfData.Data.ThreatLists)
	fmt.Printf("Related Entities: %+v\n", rfData.Data.RelatedEntities)

	fmt.Printf("\n--- Processing Evidence for '%s' ---\n", targetEnv)
	allEvidence := processEvidence(rfData.Data.Risk.EvidenceDetails, targetEnv)
	
	if len(allEvidence) == 0 {
		fmt.Println("No evidence details found.")
	} else {
		jsonBytes, err := json.MarshalIndent(allEvidence, "", "  ")
		if err != nil {
			t.Fatalf("Failed to marshal evidence: %v", err)
		}
		fmt.Println(string(jsonBytes))
	}
}
