import { splitProps, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

interface ScrollAreaProps extends JSX.HTMLAttributes<HTMLDivElement> {
  children: JSX.Element;
}

export function ScrollArea(props: ScrollAreaProps) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div
      class={cn("overflow-y-auto scrollbar-thin", local.class)}
      {...rest}
    >
      {local.children}
    </div>
  );
}
