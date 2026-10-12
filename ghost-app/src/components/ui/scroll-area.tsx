import { splitProps, onMount, onCleanup, type JSX } from "solid-js";
import { cn } from "../../lib/cn";

interface ScrollAreaProps extends JSX.HTMLAttributes<HTMLDivElement> {
  children: JSX.Element;
}

export function ScrollArea(props: ScrollAreaProps) {
  const [local, rest] = splitProps(props, ["class", "children", "ref"]);
  let ref!: HTMLDivElement;
  // A ref from the caller gets the element too.
  const setRef = (element: HTMLDivElement) => {
    ref = element;
    (local.ref as ((element: HTMLDivElement) => void) | undefined)?.(element);
  };
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
      ref={setRef}
      class={cn("scrollarea overflow-y-auto overflow-x-hidden", local.class)}
      {...rest}
    >
      {local.children}
    </div>
  );
}

/** A scroll area filling the rest of a column, its content fading out under the top and
 * bottom edges. */
export function FadedScrollArea(props: ScrollAreaProps) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div class="relative flex-1 min-h-0">
      <ScrollArea class={cn("h-full", local.class)} {...rest}>
        {local.children}
      </ScrollArea>
      <div
        class="absolute top-0 left-0 right-0 h-4 pointer-events-none z-10"
        style={{ background: "linear-gradient(to top, transparent, var(--neutral-950))" }}
      />
      <div
        class="absolute bottom-0 left-0 right-0 h-6 pointer-events-none z-10"
        style={{ background: "linear-gradient(to bottom, transparent, var(--neutral-950))" }}
      />
    </div>
  );
}
