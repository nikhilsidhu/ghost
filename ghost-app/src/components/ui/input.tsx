import { splitProps, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

export function Input(props: JSX.InputHTMLAttributes<HTMLInputElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <input
      class={cn(
        "h-8 w-full rounded px-3 text-sm",
        "bg-[var(--neutral-800)] text-[var(--neutral-100)] placeholder:text-[var(--neutral-500)]",
        "border border-[var(--neutral-700)] outline-none",
        "focus:border-[var(--purple-500)]",
        local.class,
      )}
      {...rest}
    />
  );
}
