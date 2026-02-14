import { Command, ArrowBigUp } from "lucide-solid";

const sizes = {
  sm: {
    cls: "min-w-[20px] h-[20px] px-1 text-[11px] bg-[var(--neutral-800)] text-[var(--neutral-500)] border-[var(--neutral-700)]",
    icon: 11,
  },
  md: {
    cls: "min-w-[24px] h-[24px] px-1.5 text-[12px] bg-[var(--neutral-800)] text-[var(--neutral-400)] border-[var(--neutral-700)]",
    icon: 13,
  },
  lg: {
    cls: "min-w-[28px] h-7 px-2 text-sm bg-[var(--neutral-700)] text-[var(--neutral-200)] border-[var(--neutral-600)]",
    icon: 16,
  },
} as const;

type Size = keyof typeof sizes;

export function KeyBadge(props: { value: string; size?: Size }) {
  const s = () => sizes[props.size ?? "md"];

  const inner = () => {
    switch (props.value) {
      case "Cmd":
        return <Command size={s().icon} strokeWidth={2.5} />;
      case "Ctrl":
        return "Ctrl";
      case "\u21e7":
        return <ArrowBigUp size={s().icon} strokeWidth={2.5} />;
      default:
        return <span class="font-bold leading-none">{props.value}</span>;
    }
  };

  return (
    <kbd
      class={`inline-flex items-center justify-center rounded font-semibold border ${s().cls}`}
      style={{ "font-family": "-apple-system, BlinkMacSystemFont, system-ui, sans-serif" }}
    >
      {inner()}
    </kbd>
  );
}
