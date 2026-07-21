use serde_json::Value;

pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

pub fn fetch_latest_blockhash(
    client: &dyn HttpClient,
    rpc_url: &str,
) -> Result<([u8; 32], u64), String> {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"confirmed"}]}"#;
    let resp_str = client.post_json(rpc_url, body)?;
    
    let resp: Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Invalid JSON response: {}", e))?;
        
    if let Some(err) = resp.get("error") {
        return Err(format!("RPC error: {}", err));
    }
    
    let result = resp.get("result")
        .ok_or_else(|| "Missing 'result' field in response".to_string())?;
        
    if result.is_null() {
        return Err("Result is null".to_string());
    }
    
    let value = result.get("value")
        .ok_or_else(|| "Missing 'result.value' field".to_string())?;
        
    let blockhash_b58 = value.get("blockhash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing or invalid 'blockhash'".to_string())?;
        
    let slot = result.get("context")
        .and_then(|c| c.get("slot"))
        .and_then(|s| s.as_u64())
        .ok_or_else(|| "Missing or invalid 'context.slot'".to_string())?;
        
    let decoded = bs58::decode(blockhash_b58).into_vec()
        .map_err(|e| format!("Invalid blockhash bs58: {}", e))?;
        
    if decoded.len() != 32 {
        return Err(format!("Blockhash decoded to {} bytes, expected 32", decoded.len()));
    }
    
    let mut blockhash = [0u8; 32];
    blockhash.copy_from_slice(&decoded);
    
    Ok((blockhash, slot))
}
