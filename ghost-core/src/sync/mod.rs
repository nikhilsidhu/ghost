//! What makes an account's devices converge on shared state through relays that only
//! store and forward: a clock that orders writes without trusting wall clocks, and a
//! window that recognises a message seen before, from whichever relay it arrives.

pub mod clock;
pub mod window;
