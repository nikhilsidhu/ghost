import { splitProps, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

interface NavItemProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement> {
  selected: boolean;
  /** Bright and heavier while not selected: something new to read there. */
  emphasis?: boolean;
}

/** One entry of a side list (a channel, a DM) that shows its page when clicked; the
 * selected one takes the highlight. */
export function NavItem(props: NavItemProps) {
  const [local, rest] = splitProps(props, ["selected", "emphasis", "class", "children"]);
  return (
    <button
      class={cn(
        "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-left cursor-pointer",
        local.selected
          ? "bg-[var(--active)] text-[var(--neutral-100)]"
          : local.emphasis
            ? "text-[var(--neutral-100)] font-medium hover:bg-[var(--hover)]"
            : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
        local.class,
      )}
      {...rest}
    >
      {local.children}
    </button>
  );
}
