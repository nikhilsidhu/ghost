//! libopus, which opusic-sys builds from source at one version on every platform and
//! links statically, so every device codes and conceals alike. Mono at 48 kHz.

use std::ffi::{c_int, CStr};
use std::fmt;
use std::ptr::NonNull;

use opusic_sys as ffi;

use crate::constants::SAMPLE_RATE;

/// A libopus failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpusError(c_int);

impl fmt::Display for OpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: opus_strerror returns a static, NUL-terminated message for any code.
        let message = unsafe { CStr::from_ptr(ffi::opus_strerror(self.0)) };
        f.write_str(&message.to_string_lossy())
    }
}

impl std::error::Error for OpusError {}

/// A count libopus returned, or the error it returned instead.
fn check(code: c_int) -> Result<usize, OpusError> {
    usize::try_from(code).map_err(|_| OpusError(code))
}

pub struct Encoder(NonNull<ffi::OpusEncoder>);

// SAFETY: an encoder is plain state with no thread affinity, used only through `&mut`.
unsafe impl Send for Encoder {}

impl Encoder {
    /// An encoder for speech over a network.
    pub fn voip() -> Result<Self, OpusError> {
        let mut error = 0;
        // SAFETY: a supported rate, channel count and application, and a valid out pointer.
        let raw = unsafe { ffi::opus_encoder_create(SAMPLE_RATE as i32, 1, ffi::OPUS_APPLICATION_VOIP, &mut error) };
        check(error)?;
        NonNull::new(raw).map(Self).ok_or(OpusError(ffi::OPUS_ALLOC_FAIL))
    }

    fn set(&mut self, request: c_int, value: i32) -> Result<(), OpusError> {
        // SAFETY: every request this is called with takes a single opus_int32.
        check(unsafe { ffi::opus_encoder_ctl(self.0.as_ptr(), request, value) }).map(drop)
    }

    pub fn set_bitrate(&mut self, bits_per_second: i32) -> Result<(), OpusError> {
        self.set(ffi::OPUS_SET_BITRATE_REQUEST, bits_per_second)
    }

    pub fn set_vbr(&mut self, on: bool) -> Result<(), OpusError> {
        self.set(ffi::OPUS_SET_VBR_REQUEST, on as i32)
    }

    pub fn set_complexity(&mut self, complexity: i32) -> Result<(), OpusError> {
        self.set(ffi::OPUS_SET_COMPLEXITY_REQUEST, complexity)
    }

    /// Code everything as speech, whatever the encoder might take for music.
    pub fn set_voice_signal(&mut self) -> Result<(), OpusError> {
        self.set(ffi::OPUS_SET_SIGNAL_REQUEST, ffi::OPUS_SIGNAL_VOICE)
    }

    pub fn set_inband_fec(&mut self, on: bool) -> Result<(), OpusError> {
        self.set(ffi::OPUS_SET_INBAND_FEC_REQUEST, on as i32)
    }

    pub fn set_packet_loss_perc(&mut self, percent: i32) -> Result<(), OpusError> {
        self.set(ffi::OPUS_SET_PACKET_LOSS_PERC_REQUEST, percent)
    }

    /// Encode one frame into `packet`; returns the packet's length.
    pub fn encode_float(&mut self, pcm: &[f32], packet: &mut [u8]) -> Result<usize, OpusError> {
        // SAFETY: `pcm` holds pcm.len() mono samples and `packet` has room for packet.len() bytes.
        check(unsafe {
            ffi::opus_encode_float(self.0.as_ptr(), pcm.as_ptr(), pcm.len() as c_int, packet.as_mut_ptr(), packet.len() as i32)
        })
    }

    /// One frame encoded into a packet of its own.
    #[cfg(test)]
    pub fn encode_vec_float(&mut self, pcm: &[f32]) -> Vec<u8> {
        let mut packet = vec![0u8; crate::constants::OPUS_MAX_FRAME_BYTES];
        let len = self.encode_float(pcm, &mut packet).expect("a frame encodes");
        packet.truncate(len);
        packet
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: created by opus_encoder_create and destroyed only here.
        unsafe { ffi::opus_encoder_destroy(self.0.as_ptr()) }
    }
}

pub struct Decoder(NonNull<ffi::OpusDecoder>);

// SAFETY: as for `Encoder`.
unsafe impl Send for Decoder {}

impl Decoder {
    pub fn new() -> Result<Self, OpusError> {
        let mut error = 0;
        // SAFETY: a supported rate and channel count, and a valid out pointer.
        let raw = unsafe { ffi::opus_decoder_create(SAMPLE_RATE as i32, 1, &mut error) };
        check(error)?;
        NonNull::new(raw).map(Self).ok_or(OpusError(ffi::OPUS_ALLOC_FAIL))
    }

    /// Decode `packet` into `pcm`, or with `fec` the copy it carries of the frame before
    /// it; an empty packet conceals a lost frame. Returns the samples decoded.
    pub fn decode_float(&mut self, packet: &[u8], pcm: &mut [f32], fec: bool) -> Result<usize, OpusError> {
        let data = if packet.is_empty() { std::ptr::null() } else { packet.as_ptr() };
        // SAFETY: `data` is null with a zero length or points at packet.len() bytes, and
        // `pcm` has room for pcm.len() samples.
        check(unsafe {
            ffi::opus_decode_float(self.0.as_ptr(), data, packet.len() as i32, pcm.as_mut_ptr(), pcm.len() as c_int, fec as c_int)
        })
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: created by opus_decoder_create and destroyed only here.
        unsafe { ffi::opus_decoder_destroy(self.0.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{FRAME_SAMPLES, OPUS_MAX_FRAME_BYTES};

    #[test]
    fn every_device_runs_the_same_libopus() {
        // SAFETY: a static, NUL-terminated string.
        let version = unsafe { CStr::from_ptr(ffi::opus_get_version_string()) };
        assert_eq!(version.to_str().unwrap(), "libopus 1.6.1");
    }

    #[test]
    fn a_frame_round_trips_and_errors_read_as_libopus_words() {
        let mut encoder = Encoder::voip().unwrap();
        let tone: Vec<f32> = (0..FRAME_SAMPLES).map(|i| (i as f32 * 0.05).sin() * 0.3).collect();
        let packet = encoder.encode_vec_float(&tone);
        let mut decoder = Decoder::new().unwrap();
        let mut pcm = vec![0.0f32; FRAME_SAMPLES];
        assert_eq!(decoder.decode_float(&packet, &mut pcm, false).unwrap(), FRAME_SAMPLES);
        assert_eq!(decoder.decode_float(&[], &mut pcm, false).unwrap(), FRAME_SAMPLES, "a lost frame is concealed");

        let error = encoder.encode_float(&tone[..7], &mut vec![0u8; OPUS_MAX_FRAME_BYTES]).unwrap_err();
        assert_eq!(error.to_string(), "invalid argument");
    }
}
