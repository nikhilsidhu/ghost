import { User, Palette, Headphones, Shield } from "lucide-solid";
import { registerSettings } from "./settings-registry";

const Placeholder = () => null;

const cleanups: (() => void)[] = [];

if (import.meta.hot) {
  import.meta.hot.dispose(() => { cleanups.forEach((fn) => fn()); cleanups.length = 0; });
}

cleanups.push(registerSettings({
  id: "profile",
  label: "profile",
  icon: User,
  order: 0,
  render: Placeholder,
}));

cleanups.push(registerSettings({
  id: "appearance",
  label: "appearance",
  icon: Palette,
  order: 10,
  render: Placeholder,
}));

cleanups.push(registerSettings({
  id: "audio",
  label: "audio",
  icon: Headphones,
  order: 20,
  render: Placeholder,
}));

cleanups.push(registerSettings({
  id: "privacy",
  label: "privacy",
  icon: Shield,
  order: 30,
  render: Placeholder,
}));
