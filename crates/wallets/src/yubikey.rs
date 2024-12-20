use alloy_consensus::SignableTransaction;
use alloy_dyn_abi::{Eip712Domain, TypedData};
use alloy_primitives::{hex, Address, ChainId, PrimitiveSignature, B256};
use alloy_signer::k256::ecdsa::signature;
use alloy_signer::Signer;
use alloy_sol_types::SolStruct;

extern crate secp256k1;
use crate::error::WalletSignerError;
use std::process::{Command, Output};
use secp256k1::{Secp256k1, Signature};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, SerializedSignature, Signature as EcdsaSignature};

use async_trait::async_trait;

pub type Result<T> = std::result::Result<T, WalletSignerError>;

#[derive(Debug)]
pub struct YubikeySignerStub {
}

pub type YubikeyHDPath = Vec<u8>;

impl YubikeySignerStub {
    // create signer and store address specified in `hd_path`
    pub async fn from_hd_path(hd_path: YubikeyHDPath) -> Result<Self> {
        todo!()
    }

    pub async fn get_address(&self) -> Result<Address> {
        todo!()
    }
}
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl alloy_network::TxSigner<PrimitiveSignature> for YubikeySignerStub {
    fn address(&self) -> Address {
        unimplemented!("address: unimplemented")
    }

    #[inline]
    async fn sign_transaction(
        &self,
        _tx: &mut dyn SignableTransaction<PrimitiveSignature>,
    ) -> alloy_signer::Result<PrimitiveSignature> {
        unimplemented!()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for YubikeySignerStub {
    async fn sign_hash(&self, _hash: &B256) -> alloy_signer::Result<PrimitiveSignature> {
        todo!()
    }

    #[inline]
    async fn sign_message(&self, message: &[u8]) -> alloy_signer::Result<PrimitiveSignature> {
        let hex = &hex::encode(&message);
        let args = vec!["sign", hex];
        let output = Command::new("./yubikey_wallet_signer")
            .args(args)
            .output().unwrap();
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(alloy_signer::Error::Other(Box::<dyn std::error::Error + Send + Sync + 'static>::from(stderr.to_string())));
        }
        
        let signature = Signature::from_compact(output.stdout.as_slice()).expect("Invalid signature");
        let serialized = SerializedSignature::from_signature(&signature);
        let signature_bytes: &[u8] = serialized.as_ref();
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
    async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> alloy_signer::Result<PrimitiveSignature> {
        todo!()
    }

    #[inline]
    async fn sign_dynamic_typed_data(&self, payload: &TypedData) -> alloy_signer::Result<PrimitiveSignature> {
        todo!()
    }

    #[inline]
    fn address(&self) -> Address {
        todo!()
    }

    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        todo!()
    }

    #[inline]
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        todo!()
    }
}
