use token_risk_check::rpc::*;
use token_risk_check::risk::*;
use token_risk_check::extensions::MintExtensions;

struct MockClient {
    response: String,
}

impl HttpClient for MockClient {
    fn post_json(&self, _url: &str, _body: &str) -> Result<String, String> {
        Ok(self.response.clone())
    }
}

#[test]
fn test_fetch_mint_account_well_formed() {
    // A mock JSON-RPC response with base64 data "AQIDBA==" -> [1, 2, 3, 4]
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 1 },
                "value": {
                    "data": ["AQIDBA==", "base64"],
                    "executable": false,
                    "lamports": 1000,
                    "owner": "1111",
                    "rentEpoch": 0
                }
            },
            "id": 1
        }"#.to_string(),
    };

    let data = fetch_mint_account(&client, "http://mock", "mock_mint").unwrap();
    assert_eq!(data, vec![1, 2, 3, 4]);
}

#[test]
fn test_fetch_mint_account_error_field() {
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "error": { "code": -32600, "message": "Invalid request" },
            "id": 1
        }"#.to_string(),
    };

    let res = fetch_mint_account(&client, "http://mock", "mock_mint");
    assert!(res.unwrap_err().contains("RPC error"));
}

#[test]
fn test_fetch_mint_account_not_found() {
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 1 },
                "value": null
            },
            "id": 1
        }"#.to_string(),
    };

    let res = fetch_mint_account(&client, "http://mock", "mock_mint");
    assert_eq!(res.unwrap_err(), "account not found");
}

#[test]
fn test_fetch_mint_account_malformed_data() {
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 1 },
                "value": {
                    "data": "not an array"
                }
            },
            "id": 1
        }"#.to_string(),
    };

    let res = fetch_mint_account(&client, "http://mock", "mock_mint");
    assert!(res.unwrap_err().contains("Missing or malformed data field"));
}

#[test]
fn test_fetch_largest_accounts_well_formed() {
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 1 },
                "value": [
                    { "address": "addr1", "amount": "1000" },
                    { "address": "addr2", "amount": "500" }
                ]
            },
            "id": 1
        }"#.to_string(),
    };

    let accounts = fetch_largest_accounts(&client, "http://mock", "mock_mint").unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0], ("addr1".to_string(), 1000));
    assert_eq!(accounts[1], ("addr2".to_string(), 500));
}

#[test]
fn test_fetch_largest_accounts_error() {
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "error": "Some error",
            "id": 1
        }"#.to_string(),
    };

    let res = fetch_largest_accounts(&client, "http://mock", "mock_mint");
    assert!(res.unwrap_err().contains("RPC error"));
}

#[test]
fn test_fetch_largest_accounts_malformed_amount() {
    let client = MockClient {
        response: r#"{
            "jsonrpc": "2.0",
            "result": {
                "context": { "slot": 1 },
                "value": [
                    { "address": "addr1", "amount": "1000" },
                    { "address": "addr2", "amount": "not_a_number" }
                ]
            },
            "id": 1
        }"#.to_string(),
    };

    let res = fetch_largest_accounts(&client, "http://mock", "mock_mint");
    assert!(res.unwrap_err().contains("Failed to parse amount as u128"));
}

#[test]
fn test_top_holder_concentration_bps_normal() {
    let holders = vec![
        ("addr1".to_string(), 5000),
        ("addr2".to_string(), 1000),
    ]; // sum = 6000
    let supply = 10_000;
    
    // (6000 / 10000) = 60% = 6000 bps
    let bps = top_holder_concentration_bps(&holders, supply);
    assert_eq!(bps, Some(6000));
}

#[test]
fn test_top_holder_concentration_bps_zero_supply() {
    let holders = vec![("addr1".to_string(), 1000)];
    let bps = top_holder_concentration_bps(&holders, 0);
    assert_eq!(bps, None);
}

fn empty_exts() -> MintExtensions {
    MintExtensions {
        supply: 0,
        mint_authority: None,
        freeze_authority: None,
        permanent_delegate: None,
        transfer_hook_program_id: None,
        transfer_fee_config: None,
        default_account_state: None,
    }
}

#[test]
fn test_score_concentration_none_not_checked() {
    let exts = empty_exts();
    // concentration was NOT checked (e.g. caller skipped RPC call)
    let assessment = score(&exts, &[], None, false);
    
    // Should be green by default since we explicitly opted out of checking, 
    // and no other red flags exist.
    assert_eq!(assessment.risk, "green");
}

#[test]
fn test_score_concentration_none_zero_supply() {
    let exts = empty_exts();
    // concentration WAS checked, but returned None (e.g. supply == 0)
    let assessment = score(&exts, &[], None, true);
    
    // This is a hard error signal from the network (checked but supply 0), so it's red.
    assert_eq!(assessment.risk, "red");
    assert!(assessment.reasons[0].contains("Mint supply is zero or unreadable"));
}

#[test]
fn test_score_concentration_boundaries() {
    let exts = empty_exts();

    // 2999 bps: Green
    let a = score(&exts, &[], Some(2999), true);
    assert_eq!(a.risk, "green"); // No flags escalated

    // 3000 bps: Green
    let b = score(&exts, &[], Some(3000), true);
    assert_eq!(b.risk, "green"); 

    // 3001 bps: Green (but gets a reason string)
    let c = score(&exts, &[], Some(3001), true);
    assert_eq!(c.risk, "green");
    assert!(c.reasons[0].contains(">30%"));

    // 4999 bps: Green + reason
    let d = score(&exts, &[], Some(4999), true);
    assert_eq!(d.risk, "green");

    // 5000 bps: Green + reason
    let e = score(&exts, &[], Some(5000), true);
    assert_eq!(e.risk, "green");

    // 5001 bps: Amber
    let f = score(&exts, &[], Some(5001), true);
    assert_eq!(f.risk, "amber");
    assert!(f.reasons[0].contains(">50%"));

    // 7999 bps: Amber
    let g = score(&exts, &[], Some(7999), true);
    assert_eq!(g.risk, "amber");

    // 8000 bps: Amber
    let h = score(&exts, &[], Some(8000), true);
    assert_eq!(h.risk, "amber");

    // 8001 bps: Red
    let i = score(&exts, &[], Some(8001), true);
    assert_eq!(i.risk, "red");
    assert!(i.reasons[0].contains(">80%"));
}
