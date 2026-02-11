import { invoke } from "@tauri-apps/api/core";
import type { Identity, Group, Channel, Member } from "./types";

export const getIdentity = () => invoke<Identity>("get_identity");

export const listGroups = () => invoke<Group[]>("list_groups");

export const createGroup = (name: string) =>
  invoke<Group>("create_group", { name });

export const listChannels = (groupId: string) =>
  invoke<Channel[]>("list_channels", { groupId });

export const listMembers = (groupId: string) =>
  invoke<Member[]>("list_members", { groupId });
