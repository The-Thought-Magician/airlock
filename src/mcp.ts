/**
 * A minimal MCP client over a sandbox command handle.
 *
 * Airlock's relay is deliberately transparent — it forwards frames without
 * interpreting them. But `airlock build` needs to actually *talk* to a server
 * it has just built, to record its tool definitions for pinning (§3.4) and to
 * diff them on a rebuild (§4.3). This is that client.
 */
import type { CommandHandle } from "@solarisdk/core"
import { LineReader, encode, type JsonRpcResponse } from "./jsonrpc.js"
import { WRAP_PREFIX } from "./jail.js"

export const PROTOCOL_VERSION = "2025-06-18"

/** The fields of a tool definition that a rug pull would change. */
export interface ToolDefinition {
  name: string
  description?: string
  inputSchema?: unknown
}

export interface ServerInfo {
  name?: string
  version?: string
}

export class McpSession {
  private nextId = 1
  private readonly pending = new Map<number, (r: JsonRpcResponse) => void>()
  private readonly reader: LineReader

  /**
   * @param framed  when true, the server was launched through the base64
   *   stdout wrapper, so each line is `A64:<base64>` and must be decoded before
   *   parsing. Match this to how the process was started.
   */
  constructor(
    private readonly proc: CommandHandle,
    private readonly onStderr?: (line: string) => void,
    private readonly framed = false,
  ) {
    this.reader = new LineReader((raw) => {
      const line = this.framed && raw.startsWith(WRAP_PREFIX)
        ? Buffer.from(raw.slice(WRAP_PREFIX.length), "base64").toString("utf8")
        : raw
      let msg: JsonRpcResponse
      try {
        msg = JSON.parse(line)
      } catch {
        return
      }
      if (typeof msg.id === "number" && (msg.result !== undefined || msg.error !== undefined)) {
        const resolve = this.pending.get(msg.id)
        if (resolve) {
          this.pending.delete(msg.id)
          resolve(msg)
        }
      }
    })
  }

  /** Feed a stdout chunk from the server. Wire this to `onStdout`. */
  push(chunk: string): void {
    this.reader.push(chunk)
  }

  pushStderr(chunk: string): void {
    this.onStderr?.(chunk)
  }

  async call(method: string, params?: unknown, timeoutMs = 60_000): Promise<JsonRpcResponse> {
    const id = this.nextId++
    // The timer handle is held outside the executor: referencing the promise
    // from inside its own initializer is a TDZ error.
    let timer: ReturnType<typeof setTimeout> | undefined
    const response = new Promise<JsonRpcResponse>((resolve, reject) => {
      this.pending.set(id, resolve)
      timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`MCP ${method} timed out after ${timeoutMs}ms`))
      }, timeoutMs)
    })
    try {
      await this.proc.stdin(encode({ jsonrpc: "2.0", id, method, params }))
      const res = await response
      if (res.error) {
        throw new Error(`MCP ${method} failed: ${res.error.message} (code ${res.error.code})`)
      }
      return res
    } finally {
      clearTimeout(timer)
      this.pending.delete(id)
    }
  }

  notify(method: string, params?: unknown): Promise<void> {
    return this.proc.stdin(encode({ jsonrpc: "2.0", method, params }))
  }

  /** Full handshake. Returns what the server says it is. */
  async initialize(clientName = "airlock"): Promise<ServerInfo> {
    const res = await this.call("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: clientName, version: "0.0.0" },
    })
    await this.notify("notifications/initialized")
    return ((res.result as { serverInfo?: ServerInfo })?.serverInfo ?? {}) as ServerInfo
  }

  async listTools(): Promise<ToolDefinition[]> {
    const res = await this.call("tools/list")
    return ((res.result as { tools?: ToolDefinition[] })?.tools ?? []) as ToolDefinition[]
  }
}
