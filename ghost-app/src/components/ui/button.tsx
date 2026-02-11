import { splitProps, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

type Variant = "default" | "ghost" | "danger";
type Size = "sm" | "md";

const variantStyles: Record<Variant, string> = {
  default: "bg-[var(--purple-600)] hover:bg-[var(--purple-500)] text-[var(--neutral-50)]",
  ghost: "bg-transparent hover:bg-[var(--neutral-700)] text-[var(--neutral-300)]",
  danger: "bg-[var(--red-600)] hover:bg-[var(--red-500)] text-[var(--neutral-50)]",
};

const sizeStyles: Record<Size, string> = {
  sm: "h-7 px-2 text-xs",
  md: "h-8 px-3 text-sm",
};

interface ButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export function Button(props: ButtonProps) {
  const [local, rest] = splitProps(props, ["variant", "size", "class", "children"]);
  return (
    <button
      class={cn(
        "inline-flex items-center justify-center rounded font-medium transition-colors cursor-pointer",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--purple-400)]",
        "disabled:opacity-50 disabled:cursor-not-allowed",
        variantStyles[local.variant ?? "default"],
        sizeStyles[local.size ?? "md"],
        local.class,
      )}
      {...rest}
    >
      {local.children}
    </button>
  );
}
