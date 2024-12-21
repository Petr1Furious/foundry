use std::str::FromStr;

use alloy_consensus::SignableTransaction;
use alloy_dyn_abi::{Eip712Domain, TypedData};
use alloy_primitives::address;
use alloy_primitives::ruint::aliases::U128;
use alloy_primitives::{hex, Address, ChainId, PrimitiveSignature, B256};
use alloy_signer::k256::ecdsa::signature;
use alloy_signer::Signer;
use alloy_signer::sign_transaction_with_chain_id;
use alloy_sol_types::SolStruct;
use foundry_config::figment::value;

extern crate secp256k1;

use crate::error::WalletSignerError;
use std::process::{Command, Output};
use secp256k1::Secp256k1;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, SerializedSignature, Signature};

use async_trait::async_trait;

pub type Result<T> = std::result::Result<T, WalletSignerError>;

#[derive(Debug)]
pub struct YubikeySignerStub {
    addr: Address,
    chain_id: Option<ChainId>
}

pub type YubikeyHDPath = Vec<u8>;

impl YubikeySignerStub {
    // create signer and store address specified in `hd_path`
    pub async fn from_hd_path(_hd_path: YubikeyHDPath) -> Result<Self> {
        let addr = address!("15A209f341eBddc76CBe34F8Df939be44298a769");
        Ok(Self {
            addr,
            chain_id: None,
        })
    }

    pub async fn get_address(&self) -> Result<Address> {
        Ok(self.addr)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl alloy_network::TxSigner<PrimitiveSignature> for YubikeySignerStub {
    fn address(&self) -> Address {
        self.addr
    }

    #[inline]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<PrimitiveSignature>,
    ) -> alloy_signer::Result<PrimitiveSignature> {
        sign_transaction_with_chain_id!(self, tx, self.sign_hash(&tx.signature_hash()).await)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for YubikeySignerStub {
    async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        println!("signing...");

        let hex = &hex::encode(&hash);
        let args = vec!["sign", hex, "--hash", "keccak256"];
        let output = Command::new("/usr/bin/yubikey_wallet_signer")
            .args(args)
            .output().unwrap();
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(alloy_signer::Error::Other(Box::<dyn std::error::Error + Send + Sync + 'static>::from(stderr.to_string())));
        }
        
        let out_slice = &output.stdout.as_slice();
        let uncompressed = &out_slice[out_slice.len() - 128..];
        // compact signature is 64 bytes
        
        let mut compressed = Vec::with_capacity(uncompressed.len() / 2);
        for chunk in uncompressed.chunks(2) {
            if chunk.len() == 2 {
                let combined = (chunk[0] << 4) | (chunk[1] & 0x0F);
                compressed.push(combined);
            }
        }
        
        let valid_sign: &[u8] = compressed.as_slice();
        if valid_sign.len() != 64 {
            let error_message = format!("Invalid signature length: expected 64, got {}", valid_sign.len());
            return Err(alloy_signer::Error::Other(Box::<dyn std::error::Error + Send + Sync + 'static>::from(error_message)));
        }
        let signature = Signature::from_compact(valid_sign).expect("Invalid signature");
        let serialized = SerializedSignature::from_signature(&signature);
        let signature_bytes: &[u8] = serialized.as_ref();
        return Ok(PrimitiveSignature::from_bytes_and_parity(signature_bytes, true));
        let recoverable_signature_false = RecoverableSignature::from_compact(signature_bytes, RecoveryId::from_i32(0).expect("Invalid recovery id 0"));
        
        if recoverable_signature_false.is_ok() {
            return Ok(PrimitiveSignature::from_bytes_and_parity(signature_bytes, false));
        }

        let recover_signature_true = RecoverableSignature::from_compact(signature_bytes, RecoveryId::from_i32(1).expect("Invalid recovery id 1"));
        if recover_signature_true.is_ok() {
            return Ok(PrimitiveSignature::from_bytes_and_parity(signature_bytes, true));
        }

        Err(alloy_signer::Error::Other(Box::<dyn std::error::Error + Send + Sync + 'static>::from("Parity validation failed")))
    }

    #[inline]
    fn address(&self) -> Address {
        self.addr
    }

    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    #[inline]
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}
