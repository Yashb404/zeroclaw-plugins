use depin_attest::{orchestrate_attestation, rpc::HttpClient};
use depin_attest::reading::SensorReading;
use depin_attest::provenance::MAX_STALENESS_SECS;
use ed25519_dalek::{Signer, SigningKey};

struct PanicIfCalledClient;
impl HttpClient for PanicIfCalledClient {
    fn post_json(&self, _: &str, _: &str) -> Result<String, String> {
        panic!("RPC should never be called for an unverified reading");
    }
}

struct ValidBlockhashClient;
impl HttpClient for ValidBlockhashClient {
    fn post_json(&self, _: &str, _: &str) -> Result<String, String> {
        // Return a mocked valid JSON-RPC blockhash response
        Ok(r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 123456 },
                "value": { "blockhash": "7x6q6Bxy3wE2wV1a82Lz62EaV1v4gE4z3zQ71u8a2E5E" }
            },
            "id": 1
        }"#.to_string())
    }
}

fn generate_test_payload(reading: &SensorReading, tamper_sig: bool) -> (String, String) {
    let secret = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let message_str = format!("{}|{}|{}|{}", reading.sensor_id, reading.value_str, reading.unit, reading.timestamp);
    let message = message_str.as_bytes();
    let mut signature = signing_key.sign(message).to_bytes();
    
    if tamper_sig {
        signature[0] ^= 0xff; // Invalidate signature
    }
    
    let sig_hex = hex::encode(signature);
    
    (pk_hex, sig_hex)
}

#[test]
fn test_bad_signature_never_reaches_rpc() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let (pk_hex, sig_hex) = generate_test_payload(&reading, true); // tampered

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = PanicIfCalledClient;
    let res = orchestrate_attestation(&args_json, &client, 1000000);
    
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Invalid signature"));
}

#[test]
fn test_stale_reading_never_reaches_rpc() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false); // valid signature

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = PanicIfCalledClient;
    
    // Simulate current time being exactly MAX_STALENESS_SECS + 1 after the reading timestamp
    let current_ts = 1000000 + MAX_STALENESS_SECS + 1;
    let res = orchestrate_attestation(&args_json, &client, current_ts);
    let err = res.unwrap_err();
    assert!(err.contains("too stale"), "Expected 'too stale', got {:?}", err);
}

#[test]
fn test_valid_reading_does_reach_rpc() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false); // valid signature

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = ValidBlockhashClient;
    
    // current time exactly matches reading time (0 staleness)
    let current_ts = 1000000;
    let res = orchestrate_attestation(&args_json, &client, current_ts);
    
    assert!(res.is_ok(), "Expected OK, got {:?}", res);
    let output = res.unwrap();
    assert_eq!(output.slot, 123456);
    assert_eq!(output.nonce, "device_123-123456");
    assert!(output.memo_summary.starts_with("zc-depin|device_123"));
}
