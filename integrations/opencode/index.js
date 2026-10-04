import { isAbsolute } from "node:path"
import { spawnSync } from "node:child_process"

const MAX_OUTPUT_BYTES = 64 * 1024
const DEFAULT_TIMEOUT_MS = 5_000
const RULE_ID = /^[a-z0-9][a-z0-9_.-]{0,127}$/

class GuardBlockedError extends Error {
  constructor(ruleID = "guard.evaluation_error") {
    super(`Blocked by team policy: ${ruleID}`)
    this.name = "GuardBlockedError"
  }
}

function requiredAbsolutePath(value, option) {
  if (typeof value !== "string" || !isAbsolute(value)) {
    throw new GuardBlockedError()
  }
  return value
}

function optionalAbsolutePath(value) {
  if (value === undefined) return undefined
  return requiredAbsolutePath(value)
}

function bridgeConfig(options) {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new GuardBlockedError()
  }
  if (options?.managed !== undefined && typeof options.managed !== "boolean") {
    throw new GuardBlockedError()
  }
  return {
    managed: options?.managed ?? false,
    guard: requiredAbsolutePath(options?.guard),
    policy: requiredAbsolutePath(options?.policy),
    projectPolicy: optionalAbsolutePath(options?.projectPolicy),
    auditLog: optionalAbsolutePath(options?.auditLog),
    timeoutMs,
  }
}

function invokeGuard(config, payload, event = "pre-tool") {
  const args = [
    "--adapter",
    "opencode",
    "--event",
    event,
    "--policy",
    config.policy,
  ]
  if (config.managed) args.push("--managed")
  if (config.projectPolicy) args.push("--project-policy", config.projectPolicy)
  if (config.auditLog) args.push("--audit-log", config.auditLog)

  const result = spawnSync(config.guard, args, {
    input: JSON.stringify(payload),
    encoding: "utf8",
    timeout: config.timeoutMs,
    maxBuffer: MAX_OUTPUT_BYTES,
    windowsHide: true,
  })
  if (result.error || result.signal || result.status !== 0) {
    throw new GuardBlockedError()
  }
  return result.stdout
}

function parseDecision(output) {
  let response
  try {
    response = JSON.parse(output)
  } catch {
    throw new GuardBlockedError()
  }
  if (
    !response ||
    response.schema !== 1 ||
    (response.decision !== "allow" && response.decision !== "deny")
  ) {
    throw new GuardBlockedError()
  }
  if (response.decision === "deny") {
    if (typeof response.rule_id !== "string" || !RULE_ID.test(response.rule_id)) {
      throw new GuardBlockedError()
    }
    throw new GuardBlockedError(response.rule_id)
  }
}

function parsePostResponse(output) {
  let response
  try {
    response = JSON.parse(output)
  } catch {
    throw new GuardBlockedError()
  }
  if (!response || response.schema !== 1 || response.recorded !== true) {
    throw new GuardBlockedError()
  }
}

function resultByteSize(event) {
  try {
    const value = event.status === "completed" ? event.result : event.error
    return new TextEncoder().encode(JSON.stringify(value)).byteLength
  } catch {
    return undefined
  }
}

export function createToolHook({ options, directory, run = invokeGuard }) {
  return async (event) => {
    const config = bridgeConfig(options)
    if (
      !event ||
      typeof event.tool !== "string" ||
      typeof event.sessionID !== "string" ||
      typeof event.id !== "string" ||
      !event.input ||
      typeof event.input !== "object" ||
      Array.isArray(event.input) ||
      typeof directory !== "string" ||
      !isAbsolute(directory)
    ) {
      throw new GuardBlockedError()
    }
    const output = run(config, {
      schema: 1,
      session_id: event.sessionID,
      call_id: event.id,
      cwd: directory,
      tool_name: event.tool,
      tool_input: event.input,
    })
    parseDecision(output)
  }
}

export function createPostToolHook({ options, directory, run = invokeGuard }) {
  return async (event) => {
    const config = bridgeConfig(options)
    if (
      !event ||
      typeof event.tool !== "string" ||
      typeof event.sessionID !== "string" ||
      typeof event.id !== "string" ||
      !event.input ||
      typeof event.input !== "object" ||
      Array.isArray(event.input) ||
      (event.status !== "completed" && event.status !== "error") ||
      typeof directory !== "string" ||
      !isAbsolute(directory)
    ) {
      throw new GuardBlockedError()
    }
    const size = resultByteSize(event)
    const payload = {
      schema: 1,
      session_id: event.sessionID,
      call_id: event.id,
      cwd: directory,
      tool_name: event.tool,
      tool_input: event.input,
      status: event.status,
      content_type: "application/json",
    }
    if (size !== undefined) payload.byte_size = size
    const output = run(config, payload, "post-tool")
    parsePostResponse(output)
  }
}

export default {
  id: "daguard",
  async setup(ctx) {
    const before = createToolHook({
      options: ctx.options,
      directory: ctx.location.directory,
    })
    const after = createPostToolHook({
      options: ctx.options,
      directory: ctx.location.directory,
    })
    await ctx.tool.hook("execute.before", before)
    await ctx.tool.hook("execute.after", after)
  },
}
