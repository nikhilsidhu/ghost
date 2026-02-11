import { Dialog as KDialog } from "@kobalte/core/dialog";
import type { JSX } from "solid-js";
import { cn } from "../../lib/cn";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: JSX.Element;
}

export function Dialog(props: DialogProps) {
  return (
    <KDialog open={props.open} onOpenChange={props.onOpenChange}>
      {props.children}
    </KDialog>
  );
}

export function DialogTrigger(props: { children: JSX.Element }) {
  return <KDialog.Trigger as="div">{props.children}</KDialog.Trigger>;
}

export function DialogContent(props: { children: JSX.Element; class?: string }) {
  return (
    <KDialog.Portal>
      <KDialog.Overlay class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50" />
      <div class="fixed inset-0 z-50 flex items-center justify-center">
        <KDialog.Content
          class={cn(
            "w-full max-w-md rounded-lg p-6",
            "bg-[var(--neutral-800)] border border-[var(--neutral-600)]",
            "shadow-xl",
            props.class,
          )}
        >
          {props.children}
        </KDialog.Content>
      </div>
    </KDialog.Portal>
  );
}

export function DialogTitle(props: { children: JSX.Element }) {
  return (
    <KDialog.Title class="text-sm font-medium text-[var(--neutral-100)] mb-4">
      {props.children}
    </KDialog.Title>
  );
}
