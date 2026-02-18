import { createSignal, createMemo, Show } from "solid-js";
import { encode } from "uqr";
import { Dialog, DialogContent, DialogTitle } from "./ui/dialog";
import { Button } from "./ui/button";

interface Props {
  link: string | null;
  onClose: () => void;
}

function QrCode(props: { data: string; size: number }) {
  const matrix = createMemo(() => encode(props.data));

  return (
    <svg
      viewBox={`0 0 ${matrix().size} ${matrix().size}`}
      width={props.size}
      height={props.size}
      class="rounded-lg"
      style={{ background: "var(--neutral-50)" }}
    >
      {matrix().data.map((row, y) =>
        row.map((cell, x) =>
          cell ? (
            <rect x={x} y={y} width={1} height={1} fill="var(--neutral-950)" />
          ) : null,
        ),
      )}
    </svg>
  );
}

export function InviteDialog(props: Props) {
  const [copied, setCopied] = createSignal(false);

  const handleCopy = async () => {
    if (!props.link) return;
    await navigator.clipboard.writeText(props.link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog open={!!props.link} onOpenChange={(v) => { if (!v) props.onClose(); }}>
      <DialogContent class="max-w-xs p-6">
        <DialogTitle>Invite Link</DialogTitle>

        <div class="flex flex-col items-center gap-4">
          <Show when={props.link}>
            {(link) => <QrCode data={link()} size={200} />}
          </Show>

          <div
            class="w-full px-3 py-2 rounded text-xs font-mono break-all select-all text-center"
            style={{ background: "var(--neutral-900)", color: "var(--neutral-400)" }}
          >
            {props.link}
          </div>

          <div class="flex gap-2 w-full">
            <Button class="flex-1" onClick={handleCopy}>
              {copied() ? "Copied!" : "Copy Link"}
            </Button>
            <Button variant="ghost" onClick={props.onClose}>
              Done
            </Button>
          </div>

          <p class="text-xs" style={{ color: "var(--neutral-500)" }}>
            Expires in 7 days
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
