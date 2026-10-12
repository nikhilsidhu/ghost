// What happened to the account from elsewhere: another device linked or removed one, a
// replaced key, a moved home, an account key this device cannot open, or a member whose
// identity log a relay shows differently to them and to us. Shown as banners until
// dismissed; "this device was removed" takes over the whole window instead.

import { createSignal } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { dismissAccountAlert } from "./api";
import type { AccountAlert, LiveState } from "./types";

export interface ShownAlert {
  id: number;
  alert: AccountAlert;
}

const [alerts, setAlerts] = createSignal<ShownAlert[]>([]);
const [thisDeviceRemoved, setThisDeviceRemoved] = createSignal<AccountAlert | null>(null);

export const accountAlerts = alerts;
/** The removal of this device, with what removed it; set once it happened. */
export const deviceRemoved = thisDeviceRemoved;

export const dismissAlert = (id: number) => {
  setAlerts((all) => all.filter((a) => a.id !== id));
  dismissAccountAlert(id).catch(() => {});
};

const show = (alert: AccountAlert) => {
  if (alert.kind === "this_device_removed") {
    setThisDeviceRemoved(alert);
    return;
  }
  setAlerts((all) => (all.some((a) => a.id === alert.id) ? all : [...all, { id: alert.id, alert }]));
};

/** Listen for alerts as they are raised; the live snapshot brings those raised before. */
export const listenForAccountAlerts = () => listen<AccountAlert>("account-alert", (event) => show(event.payload));

/** Raised before the listener was up, and still open. */
export const applyAlertsSnapshot = (live: LiveState) => {
  if (live.device_removed) setThisDeviceRemoved(live.device_removed);
  live.alerts.forEach(show);
};

/** Who removed this device, and where to look if it wasn't the user. */
export const describeRemoval = (removal: AccountAlert | null): string => {
  switch (removal?.removed_by) {
    case "recovery":
      return "your account was recovered on another device, which removes every other device. if that wasn't you, someone has your recovery key.";
    case "recovery_key":
      return "your recovery key removed it. if that wasn't you, someone has your recovery key.";
    case "device":
      return `${removal.remover_label || "another of your devices"} removed it. if that wasn't you, that device is where to look.`;
    default:
      return "another of your devices or your recovery key removed it.";
  }
};

export const describeAlert = (alert: AccountAlert): string => {
  const label = alert.device_label || "another device";
  switch (alert.kind) {
    case "device_linked":
      return `${label} was linked to your account.`;
    case "device_removed":
      return alert.removed_by === "recovery_key"
        ? `${label} was removed from your account with your recovery key. if that wasn't you, your recovery key is no longer safe.`
        : `${label} was removed from your account by ${alert.remover_label || "another device"}. if that wasn't you, check your devices.`;
    case "recovery_key_replaced":
      return `your recovery key was replaced from ${label}. the old key no longer works.`;
    case "home_moved":
      return "your account's home relay was moved.";
    case "bad_account_key":
      return `${label} published an account key this device can't open. if you don't recognise it, remove it.`;
    case "history_replaced": {
      const lost = alert.lost_devices.length ? ` devices that existed only there: ${alert.lost_devices.join(", ")}.` : "";
      return `a change signed with your recovery key replaced ${alert.discarded ?? "some"} entries of your account's history that a relay had shown this device.${lost} if you didn't recover or move your account, check your devices.`;
    }
    case "removal_refused":
      return `your home relay refused to record ${label}'s removal: ${alert.reason ?? "no reason given"}. it stays in your account, and sync stays paused on this device, until one of your devices records it.`;
    case "relay_refuses_device":
      return `the relay at ${alert.relay_url} says this device was removed from your account, but your home relay says it is active. that relay is behind or not to be trusted; it is tried again later.`;
    case "split_view":
      return `${alert.account_name || "a member"} sees a history of their own devices that you were never shown. a relay may be showing the two of you different things; check their device list with them before trusting a new one.`;
    default:
      return "";
  }
};
