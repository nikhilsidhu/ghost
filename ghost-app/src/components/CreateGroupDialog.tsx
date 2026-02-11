import { createSignal } from "solid-js";
import { Dialog, DialogContent, DialogTitle } from "./ui/dialog";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { createGroup } from "../lib/api";

interface Props {
  onCreated: () => void;
}

export function CreateGroupDialog(props: Props) {
  const [open, setOpen] = createSignal(false);
  const [name, setName] = createSignal("");

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    const n = name().trim();
    if (!n) return;
    await createGroup(n);
    setName("");
    setOpen(false);
    props.onCreated();
  };

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        +
      </Button>
      <Dialog open={open()} onOpenChange={setOpen}>
        <DialogContent>
          <DialogTitle>create group</DialogTitle>
          <form onSubmit={handleSubmit} class="flex flex-col gap-3">
            <Input
              placeholder="group name"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              autofocus
            />
            <div class="flex justify-end gap-2">
              <Button variant="ghost" size="sm" type="button" onClick={() => setOpen(false)}>
                cancel
              </Button>
              <Button size="sm" type="submit" disabled={!name().trim()}>
                create
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
