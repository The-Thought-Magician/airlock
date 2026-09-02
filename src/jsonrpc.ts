/**
 * Newline-delimited JSON-RPC framing, per the MCP stdio transport.
 *
 * MCP stdio is one JSON object per line — no Content-Length headers (that is
 * LSP, and confusing the two is a common way to get a silently hanging relay).
 * Messages must not contain embedded newlines, so splitting on "\n" is the
 * whole of the framing.
 *
 * Chunks arrive at arbitrary boundaries, so a message routinely spans two
 * chunks and two messages routinely share one. LineReader owns that seam.
 */

/** Accumulates arbitrary chunks and emits complete newline-terminated lines. */
export class LineReader {
  private buf = ""

  constructor(private readonly onLine: (line: string) => void) {}

  push(chunk: string): void {
    this.buf += chunk
    let nl: number
    while ((nl = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, nl)
      this.buf = this.buf.slice(nl + 1)
      // Tolerate CRLF and skip keepalive blank lines.
      const trimmed = line.endsWith("\r") ? line.slice(0, -1) : line
      if (trimmed.length > 0) this.onLine(trimmed)
    }
  }

  /** Anything left unterminated — a server that exited mid-message. */
  get pending(): string {
    return this.buf
  }
}

export type JsonRpcId = string | number

export interface JsonRpcRequest {
  jsonrpc: "2.0"
  id: JsonRpcId
  method: string
  params?: unknown
}

export interface JsonRpcNotification {
  jsonrpc: "2.0"
  method: string
  params?: unknown
}

export interface JsonRpcResponse {
  jsonrpc: "2.0"
  id: JsonRpcId
  result?: unknown
  error?: { code: number; message: string; data?: unknown }
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse

export function isResponse(m: JsonRpcMessage): m is JsonRpcResponse {
  return "id" in m && ("result" in m || "error" in m)
}

/** Serialize a message as one wire line. */
export function encode(msg: JsonRpcMessage): string {
  return JSON.stringify(msg) + "\n"
}
