use crate::device::{DeviceBundle, DeviceId, DeviceKeypair};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid verifying key")]
    InvalidKey,
    #[error("device id mismatch")]
    DeviceMismatch,
    #[error("not authorized to approve")]
    NotAuthorized,
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceLinkPayload {
    pub new_device: DeviceBundle,
    pub requested_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRequest {
    pub payload: DeviceLinkPayload,
    pub request_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkApproval {
    pub payload: DeviceLinkPayload,
    pub approved_by: DeviceId,
    pub approver_vk: [u8; 32],
    pub approval_sig: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct LinkRegistry {
    trusted: HashMap<DeviceId, DeviceBundle>,
}

impl LinkRegistry {
    pub fn new(_root: DeviceId) -> Self {
        Self {
            trusted: HashMap::new(),
        }
    }

    pub fn trust_local(&mut self, kp: &DeviceKeypair) -> Result<(), LinkError> {
        let b = kp.public_bundle();
        self.trusted.insert(b.device_id, b);
        Ok(())
    }

    pub fn is_linked(&self, id: &DeviceId) -> bool {
        self.trusted.contains_key(id)
    }

    pub fn linked_devices(&self) -> Vec<DeviceId> {
        self.trusted.keys().copied().collect()
    }

    pub fn create_link_request(
        &self,
        new_device: &DeviceKeypair,
    ) -> Result<LinkRequest, LinkError> {
        let payload = DeviceLinkPayload {
            new_device: new_device.public_bundle(),
            requested_at_ms: 0,
        };
        let bytes = serde_json::to_vec(&payload)?;
        let sig = new_device.signing_key().sign(&bytes);
        Ok(LinkRequest {
            payload,
            request_sig: sig.to_bytes().to_vec(),
        })
    }

    pub fn approve_link(
        &self,
        approver: &DeviceKeypair,
        request: &LinkRequest,
    ) -> Result<LinkApproval, LinkError> {
        if !self.is_linked(&approver.device_id()) {
            return Err(LinkError::NotAuthorized);
        }
        let new_vk = request
            .payload
            .new_device
            .verifying_key()
            .map_err(|_| LinkError::InvalidKey)?;
        let expected_id = DeviceId::from_verifying_key(&new_vk);
        if expected_id != request.payload.new_device.device_id {
            return Err(LinkError::DeviceMismatch);
        }
        let bytes = serde_json::to_vec(&request.payload)?;
        let sig_arr: [u8; 64] = request
            .request_sig
            .as_slice()
            .try_into()
            .map_err(|_| LinkError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        new_vk
            .verify(&bytes, &sig)
            .map_err(|_| LinkError::InvalidSignature)?;

        let approval_body = serde_json::to_vec(&request.payload)?;
        let approval_sig = approver.signing_key().sign(&approval_body);
        Ok(LinkApproval {
            payload: request.payload.clone(),
            approved_by: approver.device_id(),
            approver_vk: *approver.verifying_key().as_bytes(),
            approval_sig: approval_sig.to_bytes().to_vec(),
        })
    }

    pub fn apply_approval(&mut self, approval: &LinkApproval) -> Result<(), LinkError> {
        if !self.is_linked(&approval.approved_by) {
            return Err(LinkError::NotAuthorized);
        }
        let approver_vk =
            VerifyingKey::from_bytes(&approval.approver_vk).map_err(|_| LinkError::InvalidKey)?;
        let approver_id = DeviceId::from_verifying_key(&approver_vk);
        if approver_id != approval.approved_by {
            return Err(LinkError::DeviceMismatch);
        }
        let body = serde_json::to_vec(&approval.payload)?;
        let sig_arr: [u8; 64] = approval
            .approval_sig
            .as_slice()
            .try_into()
            .map_err(|_| LinkError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        approver_vk
            .verify(&body, &sig)
            .map_err(|_| LinkError::InvalidSignature)?;

        let new_vk = approval
            .payload
            .new_device
            .verifying_key()
            .map_err(|_| LinkError::InvalidKey)?;
        let new_id = DeviceId::from_verifying_key(&new_vk);
        if new_id != approval.payload.new_device.device_id {
            return Err(LinkError::DeviceMismatch);
        }
        self.trusted
            .insert(new_id, approval.payload.new_device.clone());
        Ok(())
    }
}
