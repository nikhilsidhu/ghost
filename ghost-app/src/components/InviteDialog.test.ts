import { describe, expect, it } from "vitest";
import { expiryNote } from "./InviteDialog";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe("expiryNote", () => {
  it("says when the invite ends in the largest whole unit", () => {
    expect(expiryNote(3 * DAY, 0)).toBe("Expires in 3 days");
    expect(expiryNote(DAY + 23 * HOUR, 0)).toBe("Expires in 1 day");
    expect(expiryNote(5 * HOUR + 59 * MINUTE, 0)).toBe("Expires in 5 hours");
    expect(expiryNote(2 * MINUTE, 0)).toBe("Expires in 2 minutes");
  });

  it("never says zero minutes, and says when it has ended", () => {
    expect(expiryNote(10_000, 0)).toBe("Expires in 1 minute");
    expect(expiryNote(5, 5)).toBe("Expired");
  });
});
