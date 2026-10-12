// Account alerts against a mocked backend: this device's removal takes over the window
// with what removed it, whether it arrives as an event or in the live snapshot, and is
// worded by its cause.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { AccountAlert, LiveState, RemovedBy } from "./types";

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

const removal = (removed_by: RemovedBy | null, remover_label: string | null = null): AccountAlert => ({
  id: 0, kind: "this_device_removed", device_label: null, device_key: null, relay_vk: null, generation: null,
  account_name: null, relay_url: null, discarded: null, lost_devices: [], removed_by, remover_label, reason: null,
});

describe("this device's removal", () => {
  beforeEach(() => {
    vi.resetModules();
    mockIPC(() => null, { shouldMockEvents: true });
  });
  afterEach(clearMocks);

  it("keeps what removed it when the event arrives", async () => {
    const alerts = await import("./alerts");
    await alerts.listenForAccountAlerts();
    expect(alerts.deviceRemoved()).toBeNull();

    await emit("account-alert", removal("device", "laptop"));
    await settle();
    expect(alerts.deviceRemoved()?.remover_label).toBe("laptop");
    expect(alerts.accountAlerts()).toEqual([]);
    expect(alerts.describeRemoval(alerts.deviceRemoved())).toContain("laptop removed it");
  });

  it("comes from the live snapshot for a window opened after it", async () => {
    const alerts = await import("./alerts");
    const live = { alerts: [], device_removed: removal("recovery") } as unknown as LiveState;
    alerts.applyAlertsSnapshot(live);
    expect(alerts.deviceRemoved()?.removed_by).toBe("recovery");
  });

  it("does not blame another device for a recovery", async () => {
    const { describeRemoval } = await import("./alerts");
    const recovered = describeRemoval(removal("recovery"));
    expect(recovered).toContain("recovered on another device");
    expect(recovered).not.toContain("removed it");
    expect(describeRemoval(removal("recovery_key"))).toContain("recovery key removed it");
    expect(describeRemoval(removal(null))).toContain("another of your devices or your recovery key");
  });
});
