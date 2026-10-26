use crate::ProtocolError;

/// Limits are policy constraints, not negotiated MTU or wire fields.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolLimits {
    pub max_frame_size: usize,
    pub max_payload_size: usize,
    pub max_string_size: usize,
    pub max_collection_items: usize,
    /// Aggregate route state across batches, independent of the u8 count in a frame.
    pub max_route_entries: usize,
    pub max_datagram_size: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_size: 63999,
            max_payload_size: 63995,
            max_string_size: 4096,
            max_collection_items: 255,
            max_route_entries: 4096,
            max_datagram_size: 8192,
        }
    }
}

impl ProtocolLimits {
    pub(crate) fn frame(&self, length: usize) -> Result<(), ProtocolError> {
        if !(5..=63999).contains(&length) {
            return Err(ProtocolError::InvalidLength);
        }
        if length > self.max_frame_size || length - 4 > self.max_payload_size {
            return Err(ProtocolError::Limit("control frame"));
        }
        Ok(())
    }
}
