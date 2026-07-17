use crate::extensions::{MintExtensions, TransferFeeConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct RiskAssessment {
    pub risk: String,
    pub reasons: Vec<String>,
}

pub fn score(ext: &MintExtensions, known_hooks: &[String]) -> RiskAssessment {
    let mut reasons = Vec::new();
    let mut is_red = false;
    let mut is_amber = false;

    if ext.permanent_delegate.is_some() {
        is_red = true;
        reasons.push("Permanent delegate is enabled; tokens can be burned or transferred by the delegate at any time.".to_string());
    }

    if let Some(state) = ext.default_account_state {
        if state == 2 {
            is_red = true;
            reasons.push("Default account state is Frozen; all new accounts are frozen by default.".to_string());
        }
    }

    if let Some(TransferFeeConfig { transfer_fee_basis_points, withdraw_withheld_authority: _ }) = ext.transfer_fee_config {
        if transfer_fee_basis_points > 1000 {
            is_amber = true;
            reasons.push(format!("Transfer fee is unusually high ({} bps).", transfer_fee_basis_points));
        } else if transfer_fee_basis_points > 0 {
            reasons.push(format!("Transfer fee of {} bps is enabled.", transfer_fee_basis_points));
        }
    }

    if let Some(hook) = ext.transfer_hook_program_id {
        let hook_str = bs58::encode(hook).into_string();
        if known_hooks.contains(&hook_str) {
            reasons.push(format!("Transfer hook program is a known compliance hook ({}).", hook_str));
        } else {
            is_amber = true;
            reasons.push(format!("Unknown transfer hook program ({}) can arbitrarily block or revert transfers.", hook_str));
        }
    }

    if ext.mint_authority.is_some() {
        reasons.push("Mint authority is active; supply can be inflated.".to_string());
    }

    if ext.freeze_authority.is_some() {
        reasons.push("Freeze authority is active; individual accounts can be frozen.".to_string());
    }

    let risk = if is_red {
        "red"
    } else if is_amber {
        "amber"
    } else {
        "green"
    };

    if risk == "green" && reasons.is_empty() {
        reasons.push("No high-risk extensions found. Standard mint authorities are disabled or non-malicious.".to_string());
    }

    RiskAssessment {
        risk: risk.to_string(),
        reasons,
    }
}
