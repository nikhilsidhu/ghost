import { Palette, Mail, WifiPen, MonitorSpeaker, BellRing, HatGlasses, Rat } from "lucide-solid";
import { registerSettings } from "./settings-registry";
import AppearanceSettings from "../components/settings/AppearanceSettings";
import AppearancePreview from "../components/settings/AppearancePreview";
import MessagesSettings from "../components/settings/MessagesSettings";
import NetworkSettings from "../components/settings/NetworkSettings";
import AudiovisualSettings from "../components/settings/AudiovisualSettings";
import NotificationsSettings from "../components/settings/NotificationsSettings";
import PrivacySettings from "../components/settings/PrivacySettings";
import DevSettings from "../components/settings/DevSettings";

const cleanups: (() => void)[] = [];

if (import.meta.hot) {
  import.meta.hot.dispose(() => { cleanups.forEach((fn) => fn()); cleanups.length = 0; });
}

cleanups.push(registerSettings({
  id: "audiovisual",
  label: "audiovisual",
  icon: MonitorSpeaker,
  order: 0,
  render: AudiovisualSettings,
}));

cleanups.push(registerSettings({
  id: "appearance",
  label: "appearance",
  icon: Palette,
  order: 10,
  render: AppearanceSettings,
  preview: AppearancePreview,
}));

cleanups.push(registerSettings({
  id: "messages",
  label: "messages",
  icon: Mail,
  order: 20,
  render: MessagesSettings,
}));

cleanups.push(registerSettings({
  id: "network",
  label: "network",
  icon: WifiPen,
  order: 30,
  render: NetworkSettings,
}));

cleanups.push(registerSettings({
  id: "notifications",
  label: "notifications",
  icon: BellRing,
  order: 40,
  render: NotificationsSettings,
}));

cleanups.push(registerSettings({
  id: "privacy",
  label: "privacy",
  icon: HatGlasses,
  order: 50,
  render: PrivacySettings,
}));

cleanups.push(registerSettings({
  id: "dev",
  label: "dev",
  icon: Rat,
  order: 100,
  render: DevSettings,
}));
