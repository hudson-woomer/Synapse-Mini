package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RecordedFutureResponse defines the structure for Recorded Future IP enrichment data
type RecordedFutureResponse struct {
	Data struct {
		Entity struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"entity"`
		Risk struct {
			Score           int              `json:"score"`
			Level           int              `json:"level"`
			RiskString      string           `json:"riskString"`
			Criticality     int              `json:"criticality"`
			CriticalityLbl  string           `json:"criticalityLabel"`
			EvidenceDetails []EvidenceDetail `json:"evidenceDetails"`
		} `json:"risk"`
		Location struct {
			Organization string `json:"organization"`
			Location     struct {
				Country string `json:"country"`
				City    string `json:"city"`
			} `json:"location"`
		} `json:"location"`
		Timestamps struct {
			FirstSeen string `json:"firstSeen"`
			LastSeen  string `json:"lastSeen"`
		} `json:"timestamps"`
		Metrics []struct {
			Type  string `json:"type"`
			Value int    `json:"value"`
		} `json:"metrics"`
		ThreatLists []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"threatLists"`
		RelatedEntities any    `json:"relatedEntities"`
		IntelCard       string `json:"intelCard"`
	} `json:"data"`
}

// EvidenceDetail represents an individual evidence rule/item from Recorded Future
type EvidenceDetail struct {
	Rule             string `json:"rule"`
	Criticality      int    `json:"criticality"`
	CriticalityLabel string `json:"criticalityLabel"`
	EvidenceString   string `json:"evidenceString"`
	Timestamp        string `json:"timestamp"`
	MitigationString string `json:"mitigationString"`
	MatchesTarget    bool   `json:"matches_target_environment"`
}

// getVerdict translates a risk score into a human-readable verdict
func getVerdict(score int) string {
	switch {
	case score >= 70:
		return "Malicious"
	case score >= 40:
		return "Suspicious"
	case score >= 5:
		return "Unusual"
	default:
		return "Neutral/Clean"
	}
}

// processEvidence flags evidence that matches the target environment
func processEvidence(details []EvidenceDetail, targetEnv string) []EvidenceDetail {
	targetEnvLower := strings.ToLower(targetEnv)
	for i := range details {
		if targetEnv != "" && (strings.Contains(strings.ToLower(details[i].Rule), targetEnvLower) ||
			strings.Contains(strings.ToLower(details[i].EvidenceString), targetEnvLower)) {
			details[i].MatchesTarget = true
		}
	}
	return details
}

// fetchRecordedFutureData makes an HTTP GET request to Recorded Future API
func fetchRecordedFutureData(ip string, apiToken string) (*RecordedFutureResponse, error) {
	fields := "entity,risk,timestamps,location,intelCard,metrics,relatedEntities,threatLists"
	url := fmt.Sprintf("https://api.recordedfuture.com/v2/ip/%s?fields=%s", ip, fields)
	log.Printf("Fetching data for IP: %s", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-RFToken", apiToken)
	req.Header.Set("User-Agent", "Synapse-Mini-MCP-Server/1.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var rfResp RecordedFutureResponse
	if err := json.Unmarshal(bodyBytes, &rfResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &rfResp, nil
}

// filterEvidence filters evidence details based on a case-insensitive match with target environment
func filterEvidence(details []EvidenceDetail, targetEnv string) []EvidenceDetail {
	var filtered []EvidenceDetail
	targetEnvLower := strings.ToLower(targetEnv)

	for _, detail := range details {
		if strings.Contains(strings.ToLower(detail.Rule), targetEnvLower) ||
			strings.Contains(strings.ToLower(detail.EvidenceString), targetEnvLower) {
			filtered = append(filtered, detail)
		}
	}
	return filtered
}

// EnrichIPArgs defines the arguments for the enrich_ip_context tool
type EnrichIPArgs struct {
	IPAddress         string `json:"ip_address" jsonschema:"The IP address to enrich"`
	TargetEnvironment string `json:"target_environment" jsonschema:"The target environment (e.g. Linux, Windows, AWS)"`
}

func main() {
	// Initialize logging to stderr because stdout is used for MCP communication
	log.SetOutput(os.Stderr)
	log.Println("Starting Recorded Future MCP Server...")

	apiToken := os.Getenv("RF_API_TOKEN")
	if apiToken == "" {
		log.Fatal("RF_API_TOKEN environment variable is not set")
	}

	// Create a new MCP server
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "Recorded Future IP Enricher",
		Version: "1.0.0",
	}, nil)

	// Add the enrich_ip_context tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "enrich_ip_context",
		Description: "Enriches an IP address with Recorded Future threat intel. Designed for SOC Analysts. CRITICAL INSTRUCTION: If the Verdict is 'Malicious' or 'Suspicious', you MUST report it as a threat, EVEN IF the evidence does not explicitly match the requested TargetEnvironment. A malicious IP is a threat to all environments. ALWAYS provide an Executive Summary first (Verdict, Risk Score, Malware/Threat Actors), followed by the detailed evidence.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args EnrichIPArgs) (*mcp.CallToolResult, any, error) {
		log.Printf("Tool enrich_ip_context called with IP: %s, Env: %s", args.IPAddress, args.TargetEnvironment)

		rfData, err := fetchRecordedFutureData(args.IPAddress, apiToken)
		if err != nil {
			log.Printf("Error fetching RF data: %v", err)
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)},
				},
				IsError: true,
			}, nil, nil
		}

		// Process evidence and generate verdict
		allEvidence := processEvidence(rfData.Data.Risk.EvidenceDetails, args.TargetEnvironment)
		verdict := getVerdict(rfData.Data.Risk.Score)

		// Construct the final payload to return to the LLM
		resultPayload := struct {
			IP              string  `json:"ip"`
			Verdict         string  `json:"verdict"`
			RiskScore       int     `json:"risk_score"`
			RiskLevel       int     `json:"risk_level"`
			RiskString      string  `json:"risk_string"`
			Organization    string  `json:"organization"`
			Country         string  `json:"country"`
			City            string  `json:"city"`
			FirstSeen       string  `json:"first_seen"`
			LastSeen        string  `json:"last_seen"`
			IntelCard       string  `json:"intel_card_url"`
			ThreatLists     any     `json:"threat_lists,omitempty"`
			RelatedEntities any     `json:"related_entities,omitempty"`
			Metrics         any     `json:"metrics,omitempty"`
			EvidenceSummary []EvidenceDetail `json:"evidence_details"`
		}{
			IP:              rfData.Data.Entity.Name,
			Verdict:         verdict,
			RiskScore:       rfData.Data.Risk.Score,
			RiskLevel:       rfData.Data.Risk.Level,
			RiskString:      rfData.Data.Risk.RiskString,
			Organization:    rfData.Data.Location.Organization,
			Country:         rfData.Data.Location.Location.Country,
			City:            rfData.Data.Location.Location.City,
			FirstSeen:       rfData.Data.Timestamps.FirstSeen,
			LastSeen:        rfData.Data.Timestamps.LastSeen,
			IntelCard:       rfData.Data.IntelCard,
			ThreatLists:     rfData.Data.ThreatLists,
			RelatedEntities: rfData.Data.RelatedEntities,
			Metrics:         rfData.Data.Metrics,
			EvidenceSummary: allEvidence,
		}

		jsonBytes, err := json.MarshalIndent(resultPayload, "", "  ")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "Error: Failed to marshal result payload"},
				},
				IsError: true,
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(jsonBytes)},
			},
		}, nil, nil
	})

	// Run the server on the stdio transport
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
