//! Smoke tests of the desktop app's interface: the real app, driven through
//! tauri-driver as a person would use it, with headless devices as the other people in
//! the conversation and an in-process relay. They check the wiring from the interface
//! into core; the scenario tiers check the protocol itself.
//!
//! Linux only. They need the app built with `npx tauri build --debug --no-bundle` (its
//! path in `GHOST_UI_APP`), `tauri-driver` and `WebKitWebDriver` on the path, and a
//! display (Xvfb). See TESTING.md.

// The app is launched through a shell script, which Windows can't run.
#![cfg(unix)]

mod support;

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use ghost_core::wire::derive_default_channel_id;
use support::*;
use thirtyfour::prelude::*;
use thirtyfour::Key;
use tokio::process::{Child, Command};

/// How long the interface gets to show something before a test fails.
const UI_WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(100);

/// Poll `check` until it yields a value, failing the test with `what` after `UI_WAIT`.
async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + UI_WAIT;
    loop {
        if let Some(found) = check().await {
            return found;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("the app never showed {what}");
        }
        tokio::time::sleep(POLL).await;
    }
}

fn testid(id: &str) -> By {
    By::Css(format!("[data-testid='{id}']"))
}

/// An element's text as the page has it. WebKit's WebDriver leaves out text clipped by
/// `text-overflow` (the channel names) from its own idea of visible text.
async fn inner_text(element: &WebElement) -> Option<String> {
    element.prop("innerText").await.ok().flatten()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The desktop app, launched fresh with its own data directory.
struct App {
    driver: WebDriver,
    _tauri_driver: Child,
    /// The app's own output; WebKitWebDriver would otherwise discard it.
    log: PathBuf,
    _dir: tempfile::TempDir,
}

/// Lines the failure message quotes from the end of the app's log.
const LOG_TAIL_LINES: usize = 40;

/// A script that runs the app with its output appended to `log`, for WebDriver to
/// launch in its place.
fn logging_wrapper(dir: &std::path::Path, application: &std::path::Path, log: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let wrapper = dir.join("ghost-app-logged");
    let script = format!(
        "#!/bin/sh\necho \"launched $0\" >>'{log}'\nexec '{app}' \"$@\" >>'{log}' 2>&1\n",
        app = application.display(),
        log = log.display()
    );
    std::fs::write(&wrapper, script).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    wrapper
}

impl App {
    async fn launch(relay_url: &str) -> Self {
        let application = PathBuf::from(std::env::var("GHOST_UI_APP").expect("GHOST_UI_APP names the built app"));
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        let application = logging_wrapper(dir.path(), &application, &log);
        let (port, native_port) = (free_port(), free_port());
        let tauri_driver = Command::new("tauri-driver")
            .args(["--port", &port.to_string(), "--native-port", &native_port.to_string()])
            .env("GHOST_DATA_DIR", dir.path())
            .env("GHOST_RELAY_URL", relay_url)
            .kill_on_drop(true)
            .spawn()
            .expect("tauri-driver on the path");
        eventually("tauri-driver listening", || async move {
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()
        })
        .await;
        // tauri-driver serves before the WebKitWebDriver it starts is listening, and passes
        // a session request on to it straight away.
        eventually("WebKitWebDriver listening", || async move {
            tokio::net::TcpStream::connect(("127.0.0.1", native_port)).await.ok()
        })
        .await;
        let mut capabilities = Capabilities::new();
        capabilities.set("tauri:options", serde_json::json!({ "application": application })).unwrap();
        let driver = WebDriver::new(format!("http://127.0.0.1:{port}"), capabilities).await.expect("a WebDriver session");
        Self { driver, _tauri_driver: tauri_driver, log, _dir: dir }
    }

    /// End the WebDriver session. Left to its drop, thirtyfour ends it with a blocking
    /// call that stalls this test's runtime, and with it the in-process relay the app
    /// is talking to, until the call times out.
    async fn close(self) {
        self.driver.quit().await.expect("the WebDriver session ends");
    }

    /// `eventually`, but a timeout reports what the app was showing instead, and saves
    /// a screenshot into `GHOST_UI_ARTIFACTS` when that is set.
    async fn eventually<T, F, Fut>(&self, what: &str, mut check: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        let deadline = tokio::time::Instant::now() + UI_WAIT;
        loop {
            if let Some(found) = check().await {
                return found;
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        let showing = match self.driver.execute("return document.body.innerText", vec![]).await {
            Ok(text) => text.json().as_str().unwrap_or_default().to_string(),
            Err(e) => format!("(page unreadable: {e})"),
        };
        if let Ok(dir) = std::env::var("GHOST_UI_ARTIFACTS") {
            let name: String = what.chars().map(|c| if c.is_alphanumeric() { c } else { '-' }).collect();
            let _ = std::fs::create_dir_all(&dir);
            let _ = self.driver.screenshot(&PathBuf::from(dir).join(format!("{name}.png"))).await;
        }
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        let tail = lines[lines.len().saturating_sub(LOG_TAIL_LINES)..].join("\n");
        panic!("the app never showed {what}; it showed:\n{showing}\n--- end of its log:\n{tail}");
    }

    async fn element(&self, id: &str) -> WebElement {
        self.eventually(id, || async { self.driver.find(testid(id)).await.ok() }).await
    }

    /// Texts of every element with test id `id`.
    async fn texts(&self, id: &str) -> Vec<String> {
        let mut texts = Vec::new();
        for element in self.driver.find_all(testid(id)).await.unwrap_or_default() {
            if let Some(text) = inner_text(&element).await {
                texts.push(text);
            }
        }
        texts
    }

    /// The first element with test id `id` whose text contains `text`.
    async fn element_with_text(&self, id: &str, text: &str) -> WebElement {
        self.eventually(&format!("{id} \"{text}\""), || async {
            for element in self.driver.find_all(testid(id)).await.ok()? {
                if inner_text(&element).await.is_some_and(|t| t.contains(text)) {
                    return Some(element);
                }
            }
            None
        })
        .await
    }

    async fn wait_until_gone(&self, id: &str, text: &str) {
        self.eventually(&format!("{id} \"{text}\" gone"), || async {
            (!self.texts(id).await.iter().any(|t| t.contains(text))).then_some(())
        })
        .await;
    }

    /// Create the account through onboarding: the recovery key is shown once and typed
    /// back before anything is sent, as a careful user does.
    async fn onboard(&self, name: &str) {
        self.element("setup-name").await.send_keys(name).await.unwrap();
        self.element("setup-start").await.click().await.unwrap();
        let key = inner_text(&self.element("recovery-key").await).await.expect("the recovery key is shown");
        self.element("recovery-key-saved").await.click().await.unwrap();
        self.element("recovery-key-typed").await.send_keys(&key).await.unwrap();
        self.element("recovery-key-confirm").await.click().await.unwrap();
        // The main window replaces the setup screen once the account is ready; a shortcut
        // pressed before then reaches no listener.
        self.element("main-window").await;
    }

    /// Run a palette command, typing each argument and accepting it (or its top
    /// completion) with Enter. Arguments with defaults (the open server) fill themselves.
    async fn command(&self, command: &str, args: &[&str]) {
        self.driver
            .action_chain()
            .key_down(Key::Control)
            .key_down(Key::Shift)
            .send_keys("k")
            .key_up(Key::Shift)
            .key_up(Key::Control)
            .perform()
            .await
            .unwrap();
        let input = self.element("palette-input").await;
        input.send_keys(command).await.unwrap();
        input.send_keys(Key::Enter).await.unwrap();
        for arg in args {
            let input = self.element("palette-input").await;
            input.send_keys(*arg).await.unwrap();
            input.send_keys(Key::Enter).await.unwrap();
        }
        // The palette closes with an animation; until it has, its overlay takes clicks.
        self.eventually(&format!("the palette closed after {command}"), || async {
            self.driver.find_all(By::Css("[data-palette-overlay]")).await.ok()?.is_empty().then_some(())
        })
        .await;
    }

    /// Create a server and open its general channel.
    async fn create_server(&self, name: &str) {
        self.command("create server", &[name]).await;
        let icon = self.eventually(&format!("server {name}"), || async {
            self.driver.find(By::Css(format!("[data-testid='server'][aria-label='{name}']"))).await.ok()
        })
        .await;
        icon.click().await.unwrap();
        // A click on the channel as the server opens was lost once on CI (not seen
        // locally), so click it until the channel shows.
        self.eventually("the general channel open", || async {
            if self.driver.find(testid("composer")).await.is_ok() {
                return Some(());
            }
            for channel in self.driver.find_all(testid("channel")).await.ok()? {
                if inner_text(&channel).await.is_some_and(|text| text.contains("general")) {
                    let _ = channel.click().await;
                    break;
                }
            }
            None
        })
        .await;
    }

    async fn say(&self, text: &str) {
        let composer = self.element("composer").await;
        composer.send_keys(text).await.unwrap();
        composer.send_keys(Key::Enter).await.unwrap();
    }

    /// Create an invite to the open server; returns its (token, key).
    async fn invite(&self) -> (String, [u8; 32]) {
        self.command("invite", &[]).await;
        let link = self.eventually("an invite link", || async {
            let text = inner_text(&self.driver.find(testid("invite-link")).await.ok()?).await?;
            text.contains("token=").then_some(text)
        })
        .await;
        self.element("invite-done").await.click().await.unwrap();
        let param = |name: &str| {
            link.split(['?', '&'])
                .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("invite link {link} has no {name}"))
                .to_string()
        };
        // Token and key are hex, so they come through the query string unescaped.
        (param("token"), invite_key(&param("k")))
    }
}

/// The invite key from its hex link parameter.
fn invite_key(value: &str) -> [u8; 32] {
    hex::decode(value).ok().and_then(|bytes| bytes.try_into().ok()).unwrap_or_else(|| panic!("invite key {value} is not 32 hex bytes"))
}

/// A relay, the app onboarded as alice with a server "club" open, and the server's id.
async fn app_with_server() -> (ghost_relay::server::RunningRelay, App) {
    let relay = start_relay().await;
    let app = App::launch(&relay.url()).await;
    app.onboard("alice").await;
    app.create_server("club").await;
    (relay, app)
}

/// A headless device joined to the open server by an invite the app made.
async fn invited_peer(app: &App, relay_url: &str, name: &'static str) -> (Peer, [u8; 32]) {
    let (token, key) = app.invite().await;
    let peer = Peer::new(relay_url, name).await;
    let server_id = peer.device.join(&token, &key).await.expect("joining by the app's invite");
    app.element_with_text("member", name).await;
    (peer, server_id)
}

#[tokio::test]
#[ignore = "needs the built app, tauri-driver and a display; see TESTING.md"]
async fn onboard_create_a_server_and_chat() {
    let (_relay, app) = app_with_server().await;
    app.say("hello from the app").await;
    app.element_with_text("message-content", "hello from the app").await;
    app.close().await;
}

#[tokio::test]
#[ignore = "needs the built app, tauri-driver and a display; see TESTING.md"]
async fn a_peer_joins_from_an_invite_and_chats() {
    let (relay, app) = app_with_server().await;
    let (bob, server_id) = invited_peer(&app, &relay.url(), "bob").await;
    let general = derive_default_channel_id(&server_id);

    bob.device.say(&server_id, &general, "hi from bob").await.unwrap();
    app.element_with_text("message-content", "hi from bob").await;

    let mark = bob.device.mark();
    app.say("hi bob").await;
    bob.expect(mark, "the app's reply", message_text("hi bob")).await;
    app.close().await;
}

#[tokio::test]
#[ignore = "needs the built app, tauri-driver and a display; see TESTING.md"]
async fn a_private_channel_for_a_role_reaches_only_that_role() {
    let (relay, app) = app_with_server().await;
    let (bob, server_id) = invited_peer(&app, &relay.url(), "bob").await;
    let (carol, _) = invited_peer(&app, &relay.url(), "carol").await;

    app.command("create role", &["helpers", "invite"]).await;
    app.command("assign role", &["bob", "helpers"]).await;
    app.command("create private channel", &["lounge", "helpers"]).await;
    app.element_with_text("channel", "lounge").await;

    let sees_lounge = |peer: &Peer| {
        let client = peer.device.client.clone();
        async move {
            let channels = client.lock().await.store().list_channels(&server_id).unwrap_or_default();
            channels.iter().any(|c| c.name == "lounge")
        }
    };
    eventually("bob seeing the lounge", || async { sees_lounge(&bob).await.then_some(()) }).await;
    // Bob's view has caught up; Carol's would have too by now.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!sees_lounge(&carol).await, "carol, without the role, can see the lounge");
    app.close().await;
}

#[tokio::test]
#[ignore = "needs the built app, tauri-driver and a display; see TESTING.md"]
async fn kicking_from_the_member_list() {
    let (relay, app) = app_with_server().await;
    let (bob, server_id) = invited_peer(&app, &relay.url(), "bob").await;

    let mark = bob.device.mark();
    let row = app.element_with_text("member", "bob").await;
    // WebKitWebDriver ends a right-click with a left-button release and a click, which
    // closes the member menu as soon as it opens; a real right-click sends no click. So
    // the test delivers the context menu event itself, to the same handler.
    app.driver
        .execute(
            "const r = arguments[0].getBoundingClientRect(); arguments[0].dispatchEvent(new MouseEvent('contextmenu', \
             { bubbles: true, cancelable: true, button: 2, clientX: r.x + r.width / 2, clientY: r.y + r.height / 2 }));",
            vec![row.to_json().unwrap()],
        )
        .await
        .unwrap();
    app.element("kick-member").await.click().await.unwrap();
    // The first click asks for confirmation; the second kicks.
    app.element_with_text("kick-member", "Kick them out").await.click().await.unwrap();

    bob.expect(mark, "being kicked", kicked_from(server_id)).await;
    app.wait_until_gone("member", "bob").await;
    app.close().await;
}



