import { createSignal, onCleanup } from "solid-js";
import { cn } from "../../lib/cn";
import { Button } from "./button";

/** How long a destructive button waits for its second click. */
const CONFIRM_MS = 3000;

/** A button that asks for a second click before doing something that cannot be undone. */
export function ConfirmButton(props: { label: string; confirm: string; onConfirm: () => void; disabled?: boolean; variant?: "ghost" | "outline" }) {
  const [armed, setArmed] = createSignal(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => clearTimeout(timer));
  const click = () => {
    if (armed()) {
      clearTimeout(timer);
      setArmed(false);
      props.onConfirm();
      return;
    }
    setArmed(true);
    timer = setTimeout(() => setArmed(false), CONFIRM_MS);
  };
  return (
    <Button variant={props.variant ?? "ghost"} size="sm" class={cn(armed() && "text-[var(--red-400)]")} disabled={props.disabled} onClick={click}>
      {armed() ? props.confirm : props.label}
    </Button>
  );
}
