import { invoke } from "@tauri-apps/api/core";
import type { Identity, Group, Channel, Member, Message } from "./types";

export const getIdentity = () => invoke<Identity>("get_identity");

export const listGroups = () => invoke<Group[]>("list_groups");

export const createGroup = (name: string) =>
  invoke<Group>("create_group", { name });

export const listChannels = (groupId: string) =>
  invoke<Channel[]>("list_channels", { groupId });

export const listMembers = (groupId: string) =>
  invoke<Member[]>("list_members", { groupId });

export const pinGroup = (groupId: string) =>
  invoke<void>("pin_group", { groupId });

export const unpinGroup = (groupId: string) =>
  invoke<void>("unpin_group", { groupId });

export const listPinnedGroups = () =>
  invoke<string[]>("list_pinned_groups");

export const listMessages = (channelId: string, before?: number, limit?: number) =>
  invoke<Message[]>("list_messages", { channelId, before, limit });

export const sendMessage = (groupId: string, channelId: string, content: string) =>
  invoke<Message>("send_message", { groupId, channelId, content });
