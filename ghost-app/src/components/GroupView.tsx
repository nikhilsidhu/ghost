import type { Group, Member, Identity } from "../lib/types";
import { MessageView } from "./MessageView";

interface Props {
  group: Group;
  channelId: string;
  channelName: string;
  members: Member[];
  identity: Identity | null;
}

export function GroupView(props: Props) {
  return (
    <div class="flex-1 flex flex-col min-h-0">
      <div class="h-14 flex-shrink-0 flex items-center px-4">
        <span class="text-sm text-[var(--neutral-500)] mr-1">#</span>
        <span class="text-base font-medium text-[var(--neutral-200)]">
          {props.channelName}
        </span>
      </div>
      <MessageView
        groupId={props.group.group_id}
        channelId={props.channelId}
        members={props.members}
        identity={props.identity}
      />
    </div>
  );
}
