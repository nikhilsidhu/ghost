//! Tells the audio thread when the system's audio devices change: a default input or
//! output moved on, or a device came or went. A call then reopens if the devices it
//! should use are no longer the ones open. cpal reports what happens to the open streams
//! themselves; this covers what no open stream sees: a chosen device plugged back in, a
//! default input moving on (macOS reroutes only output), a default moving on under a
//! stream pinned to its device (PulseAudio), and a chosen device unplugged while the
//! sound server moves its stream elsewhere (PulseAudio again).

use std::sync::mpsc;

pub struct DeviceWatcher {
    rx: mpsc::Receiver<()>,
    #[cfg(target_os = "macos")]
    _inner: Option<macos::CoreAudioWatcher>,
    #[cfg(target_os = "windows")]
    _inner: Option<wasapi::EndpointWatcher>,
    #[cfg(target_os = "linux")]
    _inner: Option<pulse::ServerWatcher>,
}

impl DeviceWatcher {
    /// Start watching. A watcher that cannot start is logged, and calls stay on the
    /// devices they opened until those fail.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();

        #[cfg(target_os = "macos")]
        let inner = macos::CoreAudioWatcher::new(tx);
        #[cfg(target_os = "windows")]
        let inner = wasapi::EndpointWatcher::new(tx);
        #[cfg(target_os = "linux")]
        let inner = pulse::ServerWatcher::new(tx);
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        drop(tx);

        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        let _inner = inner.map_err(|e| tracing::warn!("voice: device changes not watched: {e}")).ok();

        Self {
            rx,
            #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
            _inner,
        }
    }

    /// One notice that the devices changed, if any is waiting.
    pub fn try_recv(&self) -> Option<()> {
        self.rx.try_recv().ok()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use coreaudio_sys::{
        kAudioHardwarePropertyDefaultInputDevice, kAudioHardwarePropertyDefaultOutputDevice, kAudioHardwarePropertyDevices,
        kAudioObjectPropertyElementMain, kAudioObjectPropertyScopeGlobal, kAudioObjectSystemObject, AudioObjectAddPropertyListener,
        AudioObjectID, AudioObjectPropertyAddress, AudioObjectRemovePropertyListener, OSStatus,
    };
    use std::ffi::c_void;
    use std::sync::mpsc;

    /// The system properties watched: the default devices, and the list of devices.
    const WATCHED: [AudioObjectPropertyAddress; 3] = [
        system_property(kAudioHardwarePropertyDefaultInputDevice),
        system_property(kAudioHardwarePropertyDefaultOutputDevice),
        system_property(kAudioHardwarePropertyDevices),
    ];

    const fn system_property(selector: u32) -> AudioObjectPropertyAddress {
        AudioObjectPropertyAddress { mSelector: selector, mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain }
    }

    unsafe extern "C" fn on_property_changed(
        _id: AudioObjectID,
        _num_addresses: u32,
        _addresses: *const AudioObjectPropertyAddress,
        client_data: *mut c_void,
    ) -> OSStatus {
        // Registered only for the watched properties, so any call is a change.
        let tx = &*(client_data as *const mpsc::Sender<()>);
        let _ = tx.send(());
        0
    }

    pub struct CoreAudioWatcher {
        /// Where the listeners send; boxed so its address, which they hold, stays put.
        tx: Box<mpsc::Sender<()>>,
    }

    impl CoreAudioWatcher {
        pub fn new(tx: mpsc::Sender<()>) -> Result<Self, String> {
            let watcher = CoreAudioWatcher { tx: Box::new(tx) };
            for (registered, address) in WATCHED.iter().enumerate() {
                let status = unsafe { AudioObjectAddPropertyListener(kAudioObjectSystemObject, address, Some(on_property_changed), watcher.client_data()) };
                if status != 0 {
                    watcher.remove_listeners(registered);
                    return Err(format!("CoreAudio listener {} failed: {status}", address.mSelector));
                }
            }
            Ok(watcher)
        }

        fn client_data(&self) -> *mut c_void {
            &*self.tx as *const mpsc::Sender<()> as *mut c_void
        }

        /// Remove the first `count` listeners of `WATCHED`.
        fn remove_listeners(&self, count: usize) {
            for address in &WATCHED[..count] {
                unsafe { AudioObjectRemovePropertyListener(kAudioObjectSystemObject, address, Some(on_property_changed), self.client_data()) };
            }
        }
    }

    impl Drop for CoreAudioWatcher {
        fn drop(&mut self) {
            self.remove_listeners(WATCHED.len());
        }
    }
}

#[cfg(target_os = "windows")]
mod wasapi {
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    use ::windows::core::{implement, Result, PCWSTR};
    use ::windows::Win32::Foundation::PROPERTYKEY;
    use ::windows::Win32::Media::Audio::{
        eCapture, eConsole, eRender, EDataFlow, ERole, IMMDeviceEnumerator, IMMNotificationClient, IMMNotificationClient_Impl, MMDeviceEnumerator,
        DEVICE_STATE,
    };
    use ::windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED};

    /// Passes on changes of the default console devices (the role cpal opens as the
    /// default) and endpoints coming, going, or being turned on or off.
    #[implement(IMMNotificationClient)]
    struct EndpointChanges {
        tx: mpsc::Sender<()>,
    }

    impl IMMNotificationClient_Impl for EndpointChanges_Impl {
        fn OnDefaultDeviceChanged(&self, flow: EDataFlow, role: ERole, _device: &PCWSTR) -> Result<()> {
            if role == eConsole && (flow == eRender || flow == eCapture) {
                let _ = self.tx.send(());
            }
            Ok(())
        }

        fn OnDeviceStateChanged(&self, _device: &PCWSTR, _state: DEVICE_STATE) -> Result<()> {
            let _ = self.tx.send(());
            Ok(())
        }

        fn OnDeviceAdded(&self, _device: &PCWSTR) -> Result<()> {
            let _ = self.tx.send(());
            Ok(())
        }

        fn OnDeviceRemoved(&self, _device: &PCWSTR) -> Result<()> {
            let _ = self.tx.send(());
            Ok(())
        }

        fn OnPropertyValueChanged(&self, _device: &PCWSTR, _key: &PROPERTYKEY) -> Result<()> {
            Ok(())
        }
    }

    /// The system's endpoint notifications, registered from a thread of their own so
    /// their COM apartment is apart from cpal's; dropping it unregisters them.
    pub struct EndpointWatcher {
        stop: mpsc::Sender<()>,
        thread: Option<JoinHandle<()>>,
    }

    impl EndpointWatcher {
        pub fn new(tx: mpsc::Sender<()>) -> std::result::Result<Self, String> {
            let (stop, stopped) = mpsc::channel::<()>();
            let (registered_tx, registered_rx) = mpsc::channel();
            let thread = std::thread::Builder::new()
                .name("device-watcher".into())
                .spawn(move || unsafe {
                    let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
                    let registered = initialized.ok().and_then(|()| {
                        let enumerator: IMMDeviceEnumerator = CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
                        let client: IMMNotificationClient = EndpointChanges { tx }.into();
                        enumerator.RegisterEndpointNotificationCallback(&client)?;
                        Ok((enumerator, client))
                    });
                    match registered {
                        Ok((enumerator, client)) => {
                            let _ = registered_tx.send(Ok(()));
                            let _ = stopped.recv();
                            let _ = enumerator.UnregisterEndpointNotificationCallback(&client);
                        }
                        Err(e) => {
                            let _ = registered_tx.send(Err(e.to_string()));
                        }
                    }
                    // The COM objects above are released by now, as COM requires.
                    if initialized.is_ok() {
                        CoUninitialize();
                    }
                })
                .map_err(|e| format!("device watcher thread: {e}"))?;
            match registered_rx.recv() {
                Ok(Ok(())) => Ok(Self { stop, thread: Some(thread) }),
                Ok(Err(e)) => {
                    let _ = thread.join();
                    Err(format!("audio endpoint notifications: {e}"))
                }
                Err(_) => Err("device watcher thread ended before registering".into()),
            }
        }
    }

    impl Drop for EndpointWatcher {
        fn drop(&mut self) {
            let _ = self.stop.send(());
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod pulse {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    use pulseaudio::protocol::{SubscriptionEvent, SubscriptionEventFacility, SubscriptionEventType, SubscriptionMask};

    use crate::pulse::Connection;

    /// Whether `event` can change the devices a call should use: a default sink or
    /// source moving on (a change to the server), or a device coming or going. A
    /// device's own changes (its volume, or the port it plays through) cannot.
    fn matters(event: &SubscriptionEvent) -> bool {
        match event.event_facility {
            SubscriptionEventFacility::Server => true,
            SubscriptionEventFacility::Sink | SubscriptionEventFacility::Source => event.event_type != SubscriptionEventType::Changed,
            _ => false,
        }
    }

    /// The sound server's device events, read on a thread of their own; dropping it
    /// ends the connection, and with it the thread.
    pub struct ServerWatcher {
        closer: UnixStream,
        thread: Option<JoinHandle<()>>,
    }

    impl ServerWatcher {
        pub fn new(tx: mpsc::Sender<()>) -> Result<Self, String> {
            let mut connection = Connection::open("ghost-device-watcher")?;
            connection.subscribe(SubscriptionMask::SERVER | SubscriptionMask::SINK | SubscriptionMask::SOURCE)?;
            let closer = connection.closer()?;
            let thread = std::thread::Builder::new()
                .name("device-watcher".into())
                .spawn(move || {
                    while let Ok(event) = connection.next_event() {
                        if matters(&event) && tx.send(()).is_err() {
                            break;
                        }
                    }
                })
                .map_err(|e| format!("device watcher thread: {e}"))?;
            Ok(Self { closer, thread: Some(thread) })
        }
    }

    impl Drop for ServerWatcher {
        fn drop(&mut self) {
            let _ = self.closer.shutdown(Shutdown::Both);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn event(event_facility: SubscriptionEventFacility, event_type: SubscriptionEventType) -> SubscriptionEvent {
            SubscriptionEvent { event_facility, event_type, index: Some(1) }
        }

        #[test]
        fn defaults_moving_and_devices_coming_and_going_matter_and_volume_does_not() {
            use SubscriptionEventFacility::*;
            use SubscriptionEventType::*;
            assert!(matters(&event(Server, Changed)), "a default moved on");
            assert!(matters(&event(Sink, New)) && matters(&event(Source, Removed)));
            assert!(!matters(&event(Sink, Changed)), "a volume change");
            assert!(!matters(&event(SinkInput, New)), "another app's stream");
        }
    }
}
