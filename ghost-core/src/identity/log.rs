// The identity log's types, validation and entry builders live in ghost-wire, shared
// with relays; re-exported here for the core's callers.
pub use ghost_wire::idlog::{
    DeviceInfo, EntryBody, EntryType, IdlogError, IdlogResult, LogEntry, LogState,
    entry_hash, sign_message, validate_chain, validate_entry,
};
pub use ghost_wire::log_entries::{
    counter_sign, create_account_key, create_add_device, create_device_key, create_device_key_with_signature,
    create_genesis, create_recovery, create_rename_device, create_revoke_device, create_rotate_root, create_set_home_relay,
    device_key_signature, draft_add_device, sign_entry,
};
