use alloy_consensus::SignableTransaction;
use alloy_dyn_abi::{Eip712Domain, TypedData};
use alloy_primitives::{Address, ChainId, PrimitiveSignature, B256};
use alloy_signer::Signer;
use alloy_sol_types::SolStruct;

use crate::error::WalletSignerError;

use async_trait::async_trait;

pub type Result<T> = std::result::Result<T, WalletSignerError>;

#[derive(Debug)]
pub struct YubikeySignerStub {
}

impl YubikeySignerStub {
    // Need some params?
    pub async fn new() -> Result<Self> {
        Ok(Self {})
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
        todo!()
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
