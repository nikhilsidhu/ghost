// Tauri's invoke for the backend commands in api.ts. A failed command rejects with a
// `CommandError`, whose code the UI branches on.

import { invoke as tauriInvoke, type InvokeArgs, type InvokeOptions } from "@tauri-apps/api/core";
import type { ErrorCode } from "./generated/ErrorCode";

/** A command's failure: a code to branch on and a message for the user. */
export class CommandError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "CommandError";
    this.code = code;
  }

  /** The message alone, so `String(e)` reads as the user should see it. */
  toString() {
    return this.message;
  }
}

const isCommandError = (e: unknown): e is { code: ErrorCode; message: string } =>
  typeof e === "object" && e !== null && typeof (e as { code?: unknown }).code === "string" && typeof (e as { message?: unknown }).message === "string";

/** The code of a failed command, or null for a failure that is not one. */
export const errorCode = (e: unknown): ErrorCode | null => (e instanceof CommandError ? e.code : null);

export const invoke = async <T>(cmd: string, args?: InvokeArgs, options?: InvokeOptions): Promise<T> => {
  try {
    return await tauriInvoke<T>(cmd, args, options);
  } catch (e) {
    throw isCommandError(e) ? new CommandError(e.code, e.message) : e;
  }
};
