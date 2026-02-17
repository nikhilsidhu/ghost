import { createSetting } from "../../lib/store";
import { SettingToggle } from "./controls";

export const [enterSends, setEnterSends] = createSetting("enter-sends", true);

export default function MessagesSettings() {
  return (
    <div class="px-4">
      <SettingToggle
        label="enter sends message"
        description="when off, use shift+enter to send"
        checked={enterSends()}
        onChange={setEnterSends}
      />
    </div>
  );
}
