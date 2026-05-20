use bytes::{BufMut, BytesMut};
use thiserror::Error;

const HEADER_LEN: usize = 5;
const USER_ID_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for VisionCommand {
    type Error = VisionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            command => Err(VisionError::UnknownCommand(command)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpaddedVisionBlock {
    pub command: VisionCommand,
    pub payload: BytesMut,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VisionError {
    #[error("vision block is shorter than header")]
    ShortBlock,
    #[error("vision user id mismatch")]
    UserMismatch,
    #[error("unknown vision command {0}")]
    UnknownCommand(u8),
    #[error("vision block length is inconsistent")]
    LengthMismatch,
}

pub struct VisionPadding {
    user_id: [u8; USER_ID_LEN],
    seed: [u32; 4],
    user_id_emitted: bool,
}

impl VisionPadding {
    pub fn new(user_id: [u8; USER_ID_LEN], seed: [u32; 4]) -> Self {
        Self {
            user_id,
            seed,
            user_id_emitted: false,
        }
    }

    pub fn pad(
        &mut self,
        payload: BytesMut,
        command: VisionCommand,
        deterministic_extra_padding: u16,
    ) -> BytesMut {
        let content_len = payload.len().min(u16::MAX as usize);
        let padding_len = self.padding_len(content_len, deterministic_extra_padding);
        let user_prefix_len = if self.user_id_emitted { 0 } else { USER_ID_LEN };
        let mut padded =
            BytesMut::with_capacity(user_prefix_len + HEADER_LEN + content_len + padding_len);

        if !self.user_id_emitted {
            padded.extend_from_slice(&self.user_id);
            self.user_id_emitted = true;
        }

        padded.put_u8(command as u8);
        padded.put_u16(content_len as u16);
        padded.put_u16(padding_len as u16);
        padded.extend_from_slice(&payload[..content_len]);
        padded.resize(padded.len() + padding_len, 0);

        padded
    }

    fn padding_len(&self, content_len: usize, deterministic_extra_padding: u16) -> usize {
        if deterministic_extra_padding != 0 {
            return deterministic_extra_padding as usize;
        }

        if content_len < self.seed[0] as usize {
            let padding_len = (self.seed[2] as usize).saturating_sub(content_len);
            padding_len.min(u16::MAX as usize)
        } else {
            0
        }
    }
}

pub fn unpad_vision_block(
    padded: &[u8],
    expected_user_id: &[u8; USER_ID_LEN],
) -> Result<UnpaddedVisionBlock, VisionError> {
    if padded.len() < HEADER_LEN {
        return Err(VisionError::ShortBlock);
    }

    let offset = match padded.get(..USER_ID_LEN) {
        Some(user_id) if user_id == expected_user_id => USER_ID_LEN,
        _ => match parse_header(padded, 0) {
            Ok(header) if header.total_len == padded.len() => 0,
            _ if padded.len() >= USER_ID_LEN + HEADER_LEN => {
                return Err(VisionError::UserMismatch);
            }
            Ok(_) => return Err(VisionError::LengthMismatch),
            Err(err) => return Err(err),
        },
    };

    let header = match parse_header(padded, offset) {
        Ok(header) if header.total_len == padded.len() - offset => header,
        Ok(_) => return Err(VisionError::LengthMismatch),
        Err(err) => return Err(err),
    };

    let payload_start = offset + HEADER_LEN;
    let payload_end = payload_start + header.content_len;
    Ok(UnpaddedVisionBlock {
        command: header.command,
        payload: BytesMut::from(&padded[payload_start..payload_end]),
    })
}

#[derive(Debug, Clone, Copy)]
struct VisionHeader {
    command: VisionCommand,
    content_len: usize,
    total_len: usize,
}

fn parse_header(padded: &[u8], offset: usize) -> Result<VisionHeader, VisionError> {
    if padded.len() < offset + HEADER_LEN {
        return Err(VisionError::ShortBlock);
    }

    let command = VisionCommand::try_from(padded[offset])?;
    let content_len = u16::from_be_bytes([padded[offset + 1], padded[offset + 2]]) as usize;
    let padding_len = u16::from_be_bytes([padded[offset + 3], padded[offset + 4]]) as usize;
    let total_len = HEADER_LEN + content_len + padding_len;

    Ok(VisionHeader {
        command,
        content_len,
        total_len,
    })
}
