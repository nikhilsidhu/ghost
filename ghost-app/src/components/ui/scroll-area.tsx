import { splitProps, onMount, onCleanup, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

interface ScrollAreaProps extends JSX.HTMLAttributes<HTMLDivElement> {
  children: JSX.Element;
}

export function ScrollArea(props: ScrollAreaProps) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  let ref!: HTMLDivElement;
  let timeout: ReturnType<typeof setTimeout>;

  onMount(() => {
    const onScroll = () => {
      ref.classList.add("is-scrolling");
      clearTimeout(timeout);
      timeout = setTimeout(() => ref.classList.remove("is-scrolling"), 1200);
    };
    ref.addEventListener("scroll", onScroll, { passive: true });
    onCleanup(() => {
      ref.removeEventListener("scroll", onScroll);
      clearTimeout(timeout);
    });
  });

  return (
    <div
      ref={ref}
      class={cn("scrollarea overflow-y-auto", local.class)}
      {...rest}
    >
      {local.children}
    </div>
  );
}
