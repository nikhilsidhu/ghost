import { createSetting } from "../../lib/store";
import { SettingGroup, SettingToggle } from "./controls";

export const [enterSends, setEnterSends] = createSetting("enter-sends", true);

export default function MessagesSettings() {
  return (
    <div class="pb-4">
      <SettingGroup>
        <SettingToggle
          label="enter sends message"
          description="when off, use shift+enter to send"
          checked={enterSends()}
          onChange={setEnterSends}
        />
      </SettingGroup>
    </div>
  );
}
