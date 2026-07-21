pub mod provenance;
pub mod reading;
pub mod memo;
pub mod tx;
pub mod rpc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::reading::{validate_reading, SensorReading};
use crate::provenance::verify_provenance;
use crate::rpc::{HttpClient, fetch_latest_blockhash};
use crate::memo::build_memo_instruction;
use crate::tx::{build_unsigned_v0_tx, to_base64};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub reading: SensorReading,
    pub signature_hex: String,
}

#[derive(Serialize, Debug)]
pub struct OrchestrationOutput {
    pub tx_b64: String,
    pub nonce: String,
    pub slot: u64,
    pub memo_summary: String,
}

pub fn orchestrate_attestation(
    args_json: &str,
    client: &dyn HttpClient,
    current_timestamp: i64,
) -> Result<OrchestrationOutput, String> {
    // 1. Manual __config split
    let mut raw_val: Value = serde_json::from_str(args_json)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let config_val = raw_val
        .as_object_mut()
        .and_then(|map| map.remove("__config"))
        .unwrap_or(Value::Null);

    let config: std::collections::HashMap<String, String> =
        serde_json::from_value(config_val).unwrap_or_default();

    // 2. Deserialize args
    let args: ExecuteArgs = serde_json::from_value(raw_val)
        .map_err(|e| format!("Invalid arguments: {}", e))?;

    // 3. validate_reading
    validate_reading(&args.reading)
        .map_err(|e| format!("Invalid reading: {}", e))?;

    // 4. Decode signature and device pubkey
    // Intent: simple devices share one key for all sensors (global fallback); 
    // complex gateways can issue distinct per-sensor keys for granular revocation.
    let pubkey_key = format!("{}_pubkey", args.reading.sensor_id);
    let pubkey_hex = config.get(&pubkey_key)
        .or_else(|| config.get("device_pubkey"))
        .map(|s| s.as_str())
        .ok_or_else(|| "Missing device_pubkey in config".to_string())?;

    if pubkey_hex.len() != 64 {
        return Err("Config device_pubkey must be 64 hex characters".to_string());
    }

    let mut pubkey = [0u8; 32];
    for (i, byte) in pubkey.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&pubkey_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex in device_pubkey".to_string())?;
    }

    if args.signature_hex.len() != 128 {
        return Err("signature_hex must be 128 hex characters".to_string());
    }

    let mut sig = [0u8; 64];
    for (i, byte) in sig.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args.signature_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex in signature_hex".to_string())?;
    }

    // 5. Verify provenance (must be BEFORE RPC call)
    // We sign an explicit pipe-delimited string, NOT raw JSON, to guarantee byte-for-byte 
    // exactness across any device language (C, Python, etc.) avoiding JSON formatting quirks.
    let message_str = format!("{}|{}|{}|{}", args.reading.sensor_id, args.reading.value_str, args.reading.unit, args.reading.timestamp);
    let message = message_str.as_bytes();

    verify_provenance(&pubkey, message, &sig, args.reading.timestamp, current_timestamp)
        .map_err(|e| format!("Provenance verification failed: {}", e))?;

    // 6. Fetch RPC Blockhash
    let rpc_url = config.get("rpc_url")
        .map(|s| s.as_str())
        .unwrap_or("https://api.mainnet-beta.solana.com");
        
    let (blockhash, slot) = fetch_latest_blockhash(client, rpc_url)?;

    // 7. Derive nonce
    let nonce = format!("{}-{}", args.reading.sensor_id, slot);

    // 8. Build memo text and transaction
    let memo_text = format!(
        "zc-depin|{}|{}|{}|{}|{}",
        args.reading.sensor_id, args.reading.value_str, args.reading.unit, args.reading.timestamp, nonce
    );
    let ix = build_memo_instruction(&memo_text)?;
    
    let fee_payer_b58 = config.get("fee_payer")
        .map(|s| s.as_str())
        .ok_or_else(|| "Missing 'fee_payer' in config".to_string())?;
        
    let decoded_fee_payer = bs58::decode(fee_payer_b58).into_vec()
        .map_err(|e| format!("Invalid base58 in fee_payer: {}", e))?;
        
    if decoded_fee_payer.len() != 32 {
        return Err(format!("fee_payer decoded to {} bytes, expected 32", decoded_fee_payer.len()));
    }
    
    let mut fee_payer = [0u8; 32];
    fee_payer.copy_from_slice(&decoded_fee_payer);

    let tx_bytes = build_unsigned_v0_tx(&fee_payer, &blockhash, &[ix])?;

    // 9. Base64 encode and output
    let tx_b64 = to_base64(&tx_bytes);

    Ok(OrchestrationOutput {
        tx_b64,
        nonce,
        slot,
        memo_summary: memo_text,
    })
}

#[cfg(target_family = "wasm")]
mod shim {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use crate::rpc::HttpClient;
    use std::time::SystemTime;
    
    struct WakiClient;
    impl HttpClient for WakiClient {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let req = zeroclaw::plugin::http_client::HttpRequest {
                method: zeroclaw::plugin::http_client::HttpMethod::Post,
                url: url.to_string(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: Some(body.as_bytes().to_vec()),
            };
            
            let resp = zeroclaw::plugin::http_client::send_request(&req)
                .map_err(|e| format!("HTTP request failed: {}", e))?;
                
            if resp.status_code >= 400 {
                return Err(format!("HTTP error status: {}", resp.status_code));
            }
            
            let body_bytes = resp.body.ok_or_else(|| "Empty response body".to_string())?;
            String::from_utf8(body_bytes).map_err(|e| format!("Invalid UTF-8 in response: {}", e))
        }
    }

    struct DepinAttestPlugin;

    impl PluginInfo for DepinAttestPlugin {
        fn plugin_name() -> String {
            "depin-attest".to_string()
        }

        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for DepinAttestPlugin {
        fn name() -> String {
            "depin-attest".to_string()
        }

        fn description() -> String {
            "Verify Ed25519 signatures of DePIN sensor readings and prepare a transaction.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "reading": {
                        "type": "object",
                        "description": "The sensor reading data",
                        "properties": {
                            "sensor_id": { "type": "string" },
                            "value_str": { "type": "string" },
                            "unit": { "type": "string" },
                            "timestamp": { "type": "integer" }
                        },
                        "required": ["sensor_id", "value_str", "unit", "timestamp"]
                    },
                    "signature_hex": {
                        "type": "string",
                        "description": "Hex-encoded 64-byte Ed25519 signature."
                    }
                },
                "required": ["reading", "signature_hex"]
            })
            .to_string()
        }

        fn execute(args_json: String) -> Result<ToolResult, String> {
            let finish = |success: bool, output: String, error: Option<String>| -> Result<ToolResult, String> {
                // 10. Exactly one log_record call per execute
                let mut attrs = std::collections::HashMap::new();
                attrs.insert("args_len".to_string(), args_json.len().to_string());
                
                let outcome = if success { 
                    zeroclaw::plugin::logger::PluginOutcome::Success 
                } else { 
                    zeroclaw::plugin::logger::PluginOutcome::Failure 
                };
                
                let msg = error.clone().unwrap_or_else(|| "Attestation successful".to_string());
                
                zeroclaw::plugin::logger::log_record(
                    zeroclaw::plugin::logger::LogLevel::Info,
                    &zeroclaw::plugin::logger::PluginEvent {
                        function_name: "execute".to_string(),
                        action: zeroclaw::plugin::logger::PluginAction::Evaluate,
                        outcome,
                        duration_ms: 0,
                        attrs,
                        message: msg,
                    }
                );
                
                Ok(ToolResult {
                    success,
                    output,
                    error,
                })
            };

            let current_ts = match SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(_) => return finish(false, "".to_string(), Some("System time error".to_string())),
            };
            
            let client = WakiClient;
            match crate::orchestrate_attestation(&args_json, &client, current_ts) {
                Ok(output) => {
                    let out_json = serde_json::to_string(&output).unwrap_or_default();
                    finish(true, out_json, None)
                },
                Err(e) => finish(false, "".to_string(), Some(e)),
            }
        }
    }

    export!(DepinAttestPlugin);
}
