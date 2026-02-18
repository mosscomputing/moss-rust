# MOSS Rust SDK

**Unsigned agent output is broken output.**

MOSS (Message-Origin Signing System) provides cryptographic signing for AI agents. Every output is signed with ML-DSA-44 (post-quantum), creating non-repudiable execution records with audit-grade provenance.

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
moss-sdk = "0.1"
tokio = { version = "1.0", features = ["full"] }
```

## Quick Start

```rust
use moss_sdk::{MossClient, SignRequest};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), moss_sdk::MossError> {
    // Create client (uses MOSS_API_KEY env var if set)
    let client = MossClient::new(std::env::var("MOSS_API_KEY").ok())?;

    // Sign any agent output
    let result = client.sign(SignRequest {
        payload: serde_json::json!({
            "action": "transfer",
            "amount": 500
        }),
        agent_id: "agent-finance-01".to_string(),
        action: None,
        context: None,
    }).await?;

    println!("Signed! Hash: {}", result.envelope.payload_hash);
    println!("Decision: {}", result.decision);

    // Verify offline
    let payload = serde_json::json!({"action": "transfer", "amount": 500});
    let verify_result = client.verify(&payload, &result.envelope);

    if verify_result.valid {
        println!("Verified! Signed by: {:?}", verify_result.subject);
    }

    Ok(())
}
```

## Enterprise Features

With an API key, you get policy evaluation, approval workflows, and audit logging:

```rust
let client = MossClient::new(Some("your_api_key".to_string()))?;

let result = client.sign(SignRequest {
    payload: serde_json::json!({
        "action": "high_risk_transfer",
        "amount": 1000000,
        "recipient": "external-account"
    }),
    agent_id: "finance-bot".to_string(),
    action: Some("transfer".to_string()),
    context: Some(HashMap::from([
        ("user_id".to_string(), serde_json::json!("u123")),
        ("department".to_string(), serde_json::json!("finance")),
    ])),
}).await?;

match result.decision.as_str() {
    "allow" => println!("Action allowed"),
    "block" => println!("Action blocked: {:?}", result.reason),
    "hold" => println!("Action held for approval: {:?}", result.action_id),
    _ => {}
}
```

## Agent Lifecycle Management

```rust
use moss_sdk::RegisterAgentRequest;

// Register a new agent
let agent = client.register_agent(RegisterAgentRequest {
    agent_id: "my-new-agent".to_string(),
    display_name: Some("My New Agent".to_string()),
    tags: Some(vec!["production".to_string(), "finance".to_string()]),
    metadata: None,
    policy_id: None,
}).await?;
println!("Signing secret (save this!): {}", agent.signing_secret);

// Get agent details
if let Some(existing) = client.get_agent("my-new-agent").await? {
    println!("Status: {}, Signatures: {}", existing.status, existing.total_signatures);
}

// Rotate key (returns new signing secret)
let rotate_result = client.rotate_agent_key("my-new-agent", Some("quarterly rotation")).await?;
println!("New signing secret: {}", rotate_result.signing_secret);

// Suspend agent (can be reactivated)
client.suspend_agent("my-new-agent", Some("suspicious activity")).await?;

// Reactivate agent
client.reactivate_agent("my-new-agent").await?;

// Permanently revoke agent
client.revoke_agent("my-new-agent", "compromised credentials").await?;
```

## Envelope Format

Every signed action produces a verifiable envelope:

```rust
let envelope = result.envelope;
println!("Spec: {}", envelope.spec);           // "moss-0001"
println!("Version: {}", envelope.version);      // 1
println!("Algorithm: {}", envelope.alg);        // "ML-DSA-44"
println!("Subject: {}", envelope.subject);      // Agent ID
println!("Key Version: {}", envelope.key_version);
println!("Sequence: {}", envelope.seq);
println!("Issued At: {}", envelope.issued_at);
println!("Payload Hash: {}", envelope.payload_hash);
```

## Configuration

```rust
use moss_sdk::{MossClient, MossConfig};

let client = MossClient::with_config(MossConfig {
    api_key: Some("your_api_key".to_string()),
    base_url: "https://moss-api.example.com".to_string(),
})?;
```

## Error Handling

```rust
use moss_sdk::MossError;

match client.sign(req).await {
    Ok(result) => println!("Signed!"),
    Err(MossError::NoApiKey) => println!("API key required"),
    Err(MossError::ApiError(msg)) => println!("API error: {}", msg),
    Err(e) => println!("Error: {}", e),
}
```

## Pricing Tiers

| Tier | Price | Agents | Signatures | Retention |
|------|-------|--------|------------|-----------|
| **Free** | $0 | 5 | 1,000/day | 7 days |
| **Pro** | $1,499/mo | Unlimited | Unlimited | 1 year |
| **Enterprise** | Custom | Unlimited | Unlimited | 7 years |

*Annual billing: $1,249/mo (save $3,000/year)*

All new signups get a **14-day free trial** of Pro.

## Links

- [mosscomputing.com](https://mosscomputing.com) — Project site
- [app.mosscomputing.com](https://app.mosscomputing.com) — Dashboard
- [Python SDK](https://github.com/mosscomputing/moss) — moss-sdk
- [Go SDK](https://github.com/mosscomputing/moss-go) — moss-go

## License

Proprietary - See LICENSE for terms.

Copyright (c) 2025-2026 IAMPASS Inc. All Rights Reserved.
