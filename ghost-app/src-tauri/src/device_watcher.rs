use std::sync::mpsc;

#[derive(Debug, Clone, Copy)]
pub enum DeviceEvent {
    DefaultOutputChanged,
    DefaultInputChanged,
}

pub struct DeviceWatcher {
    rx: mpsc::Receiver<DeviceEvent>,
    #[cfg(target_os = "macos")]
    _inner: macos::CoreAudioWatcher,
}

impl DeviceWatcher {
    pub fn new() -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();

        #[cfg(target_os = "macos")]
        let _inner = macos::CoreAudioWatcher::new(tx)?;

        // On unsupported platforms, the channel just never receives anything
        #[cfg(not(target_os = "macos"))]
        let _ = tx;

        Ok(Self {
            rx,
            #[cfg(target_os = "macos")]
            _inner,
        })
    }

    pub fn try_recv(&self) -> Option<DeviceEvent> {
        self.rx.try_recv().ok()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::DeviceEvent;
    use coreaudio_sys::{
        AudioObjectAddPropertyListener, AudioObjectID, AudioObjectPropertyAddress,
        AudioObjectRemovePropertyListener, OSStatus,
        kAudioHardwarePropertyDefaultInputDevice, kAudioHardwarePropertyDefaultOutputDevice,
        kAudioObjectPropertyElementMain, kAudioObjectPropertyScopeGlobal,
        kAudioObjectSystemObject,
    };
    use std::ffi::c_void;
    use std::sync::mpsc;

    const OUTPUT_ADDR: AudioObjectPropertyAddress = AudioObjectPropertyAddress {
        mSelector: kAudioHardwarePropertyDefaultOutputDevice,
        mScope: kAudioObjectPropertyScopeGlobal,
        mElement: kAudioObjectPropertyElementMain,
    };

    const INPUT_ADDR: AudioObjectPropertyAddress = AudioObjectPropertyAddress {
        mSelector: kAudioHardwarePropertyDefaultInputDevice,
        mScope: kAudioObjectPropertyScopeGlobal,
        mElement: kAudioObjectPropertyElementMain,
    };

    unsafe extern "C" fn on_property_changed(
        _id: AudioObjectID,
        num_addresses: u32,
        addresses: *const AudioObjectPropertyAddress,
        client_data: *mut c_void,
    ) -> OSStatus {
        let tx = &*(client_data as *const mpsc::Sender<DeviceEvent>);
        for i in 0..num_addresses {
            let addr = &*addresses.add(i as usize);
            let event = if addr.mSelector == kAudioHardwarePropertyDefaultOutputDevice {
                DeviceEvent::DefaultOutputChanged
            } else if addr.mSelector == kAudioHardwarePropertyDefaultInputDevice {
                DeviceEvent::DefaultInputChanged
            } else {
                continue;
            };
            let _ = tx.send(event);
        }
        0
    }

    pub struct CoreAudioWatcher {
        // Prevent the sender from being dropped while listeners are registered
        _tx: Box<mpsc::Sender<DeviceEvent>>,
    }

    impl CoreAudioWatcher {
        pub fn new(tx: mpsc::Sender<DeviceEvent>) -> Result<Self, String> {
            let tx = Box::new(tx);
            let tx_ptr = &*tx as *const mpsc::Sender<DeviceEvent> as *mut c_void;

            unsafe {
                let status = AudioObjectAddPropertyListener(
                    kAudioObjectSystemObject,
                    &OUTPUT_ADDR,
                    Some(on_property_changed),
                    tx_ptr,
                );
                if status != 0 {
                    return Err(format!("CoreAudio output listener failed: {status}"));
                }

                let status = AudioObjectAddPropertyListener(
                    kAudioObjectSystemObject,
                    &INPUT_ADDR,
                    Some(on_property_changed),
                    tx_ptr,
                );
                if status != 0 {
                    // Clean up the output listener we already registered
                    AudioObjectRemovePropertyListener(
                        kAudioObjectSystemObject,
                        &OUTPUT_ADDR,
                        Some(on_property_changed),
                        tx_ptr,
                    );
                    return Err(format!("CoreAudio input listener failed: {status}"));
                }
            }

            Ok(CoreAudioWatcher { _tx: tx })
        }
    }

    impl Drop for CoreAudioWatcher {
        fn drop(&mut self) {
            let tx_ptr = &*self._tx as *const mpsc::Sender<DeviceEvent> as *mut c_void;
            unsafe {
                AudioObjectRemovePropertyListener(
                    kAudioObjectSystemObject,
                    &OUTPUT_ADDR,
                    Some(on_property_changed),
                    tx_ptr,
                );
                AudioObjectRemovePropertyListener(
                    kAudioObjectSystemObject,
                    &INPUT_ADDR,
                    Some(on_property_changed),
                    tx_ptr,
                );
            }
        }
    }
}
