pub mod extensions;
pub mod program;
pub mod risk;
pub mod rpc;

#[cfg(target_family = "wasm")]
mod shim {
    use std::collections::HashMap;
    use serde::Deserialize;
    use waki::Client;

    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    use crate::extensions::parse_mint_extensions;
    use crate::risk::{score, top_holder_concentration_bps};
    use crate::rpc::{fetch_largest_accounts, fetch_mint_account, HttpClient};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct WakiClient;
    impl HttpClient for WakiClient {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let client = Client::new();
            let req = client.post(url)
                .body(body)
                .header("content-type", "application/json");

            let res = req.send().map_err(|e| format!("HTTP send failed: {:?}", e))?;
            
            if res.status_code() < 200 || res.status_code() >= 300 {
                return Err(format!("HTTP Error: {}", res.status_code()));
            }

            let body_bytes = res.body().map_err(|e| format!("Failed to read body: {:?}", e))?;
            String::from_utf8(body_bytes)
                .map_err(|e| format!("Invalid UTF-8 in response: {}", e))
        }
    }

    struct TokenRiskCheckPlugin;

    impl PluginInfo for TokenRiskCheckPlugin {
        fn plugin_name() -> String {
            "token-risk-check".to_string()
        }

        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for TokenRiskCheckPlugin {
        fn name() -> String {
            "token-risk-check".to_string()
        }

        fn description() -> String {
            "Evaluates risk of Token-2022 mints by decoding extensions. Returns a red/amber/green verdict.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The base58 mint address of the Solana token to check."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args_json: String) -> Result<ToolResult, String> {
            let start = std::time::Instant::now();
            
            // Helper to consistently wrap failures into Ok(ToolResult { success: false, ... }) 
            // and log the final outcome, completely avoiding the model-invisible Err(String).
            let finish = |success: bool, output: String, error: Option<String>| -> Result<ToolResult, String> {
                let outcome = if success { PluginOutcome::Success } else { PluginOutcome::Failure };
                let duration_ms = start.elapsed().as_millis() as u64;
                
                log_record(
                    LogLevel::Info,
                    &PluginEvent {
                        function_name: "execute".to_string(),
                        action: PluginAction::Complete,
                        outcome: Some(outcome),
                        duration_ms: Some(duration_ms),
                        attrs: None, 
                        message: if let Some(ref e) = error { e.clone() } else { "Risk checked successfully".to_string() },
                    }
                );

                Ok(ToolResult {
                    success,
                    output,
                    error,
                })
            };

            let args: ExecuteArgs = match serde_json::from_str(&args_json) {
                Ok(a) => a,
                Err(e) => return finish(false, "".to_string(), Some(format!("Invalid arguments: {}", e))),
            };

            match bs58::decode(&args.mint).into_vec() {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        return finish(false, "".to_string(), Some("Invalid mint address: must be exactly 32 bytes".to_string()));
                    }
                }
                Err(e) => return finish(false, "".to_string(), Some(format!("Invalid mint address: {}", e))),
            }

            let rpc_url = args.config.get("rpc_url")
                .map(|s| s.as_str())
                .unwrap_or("https://api.mainnet-beta.solana.com");
            
            let raw_hooks = args.config.get("known_hooks").map(|s| s.as_str()).unwrap_or("");
            let known_hooks: Vec<String> = raw_hooks
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let client = WakiClient;

            let mint_bytes = match fetch_mint_account(&client, rpc_url, &args.mint) {
                Ok(b) => b,
                Err(e) => return finish(false, "".to_string(), Some(e)),
            };

            let exts = match parse_mint_extensions(&mint_bytes) {
                Ok(e) => e,
                Err(e) => return finish(false, "".to_string(), Some(e)),
            };

            let largest = match fetch_largest_accounts(&client, rpc_url, &args.mint) {
                Ok(l) => l,
                Err(e) => return finish(false, "".to_string(), Some(e)),
            };

            let total_supply = exts.supply as u128;

            let concentration = top_holder_concentration_bps(&largest, total_supply);
            
            let mut hook_program_info = None;
            if let Some(hook) = exts.transfer_hook_program_id {
                let hook_str = bs58::encode(hook).into_string();
                let prog_acc = match crate::rpc::fetch_account_info(&client, rpc_url, &hook_str) {
                    Ok(a) => a,
                    Err(e) => return finish(false, "".to_string(), Some(format!("Failed to fetch hook program: {}", e))),
                };

                let ptr = match crate::program::parse_program_pointer(&prog_acc.data, &prog_acc.owner, prog_acc.executable) {
                    Ok(p) => p,
                    Err(e) => return finish(false, "".to_string(), Some(format!("Failed to parse hook program: {}", e))),
                };

                match ptr {
                    crate::program::ProgramPointer::Immutable => {
                        hook_program_info = Some(crate::program::HookProgramInfo {
                            is_executable: prog_acc.executable,
                            is_upgradeable: false,
                            upgrade_authority: None,
                        });
                    }
                    crate::program::ProgramPointer::Upgradeable(addr) => {
                        let pdata_str = bs58::encode(addr).into_string();
                        let pdata_acc = match crate::rpc::fetch_account_info(&client, rpc_url, &pdata_str) {
                            Ok(a) => a,
                            Err(e) => return finish(false, "".to_string(), Some(format!("Failed to fetch hook ProgramData: {}", e))),
                        };

                        let upgrade_authority = match crate::program::parse_programdata_account(&pdata_acc.data) {
                            Ok(auth) => auth,
                            Err(e) => return finish(false, "".to_string(), Some(format!("Failed to parse hook ProgramData: {}", e))),
                        };

                        hook_program_info = Some(crate::program::HookProgramInfo {
                            is_executable: prog_acc.executable,
                            is_upgradeable: true,
                            upgrade_authority,
                        });
                    }
                }
            }

            let assessment = score(&exts, &known_hooks, concentration, hook_program_info.as_ref()); 

            let output_str = match serde_json::to_string(&assessment) {
                Ok(s) => s,
                Err(e) => return finish(false, "".to_string(), Some(format!("Failed to serialize assessment: {}", e))),
            };

            finish(true, output_str, None)
        }
    }

    export!(TokenRiskCheckPlugin);
}
