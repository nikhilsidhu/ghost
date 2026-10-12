import { splitProps, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

/** A raised block on the page background: a settings group, a stream's figures, a detail pane. */
export function Card(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div class={cn("rounded-lg bg-[var(--neutral-900)]", local.class)} {...rest}>
      {local.children}
    </div>
  );
}
