# Synapse-Mini

Synapse-Mini is a Model Context Protocol (MCP) server written in Go that provides tools for IP address enrichment using the Recorded Future API. It allows AI agents (like Goose) to retrieve and filter threat intelligence data based on a target environment (e.g., Linux, Windows, AWS).

## Features
- **IP Enrichment:** Queries Recorded Future for risk details associated with an IP address.
- **Contextual Filtering:** Filters threat evidence strings to only include items relevant to your specific target environment.
- **MCP Integration:** Communicates via `stdio`, making it instantly compatible with MCP clients like Goose or Claude Desktop.

## Prerequisites

- [Go](https://golang.org/doc/install) (1.21 or higher recommended)
- A Recorded Future API Token

## Build Instructions

To build the executable:

```bash
go build -o synapse-mini main.go
```

## Running Tests

To verify the internal logic, run the unit tests:

```bash
go test -v ./...
```

## Goose Configuration

Since Goose acts as the MCP client, it will launch this server as a subprocess. You need to configure Goose to know where your binary is and provide it with the necessary API token.

Add the following to your Goose configuration file (typically `~/.config/goose/config.yaml` or added via the Goose CLI):

```yaml
extensions:
  synapse-mini:
    name: "Recorded Future IP Enricher"
    cmd: "/absolute/path/to/Synapse-Mini/synapse-mini"
    env:
      RF_API_TOKEN: "your_recorded_future_api_token_here"
```

*(Note: Replace `/absolute/path/to/` with the actual path to your compiled binary, or use `go run main.go` if you prefer not to compile.)*

## Available Tools

### `enrich_ip_context`
Enriches an IP address with Recorded Future data and filters it based on your target environment.

**Arguments:**
- `ip_address` (string): The IP address you want to investigate (e.g., `"8.8.8.8"`).
- `target_environment` (string): The environment context to filter for (e.g., `"Linux"`, `"AWS"`, `"Windows"`).
