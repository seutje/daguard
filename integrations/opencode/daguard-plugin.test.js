import assert from "node:assert/strict"
import test from "node:test"

import plugin, { createPostToolHook, createToolHook } from "./index.js"

const options = {
  guard: "/usr/local/bin/daguard",
  policy: "/etc/daguard/policy.json",
}
const event = {
  tool: "read",
  sessionID: "ses_test",
  id: "call_test",
  input: { filePath: "README.md" },
}

test("registers the OpenCode v2 execute.before hook", async () => {
  const registered = new Map()
  await plugin.setup({
    options,
    location: { directory: "/workspace/project" },
    tool: {
      async hook(value, handler) {
        registered.set(value, handler)
      },
    },
  })
  assert.equal(typeof registered.get("execute.before"), "function")
  assert.equal(typeof registered.get("execute.after"), "function")
})

test("post hook sends result metadata without raw result content", async () => {
  let received
  const hook = createPostToolHook({
    options,
    directory: "/workspace/project",
    run(config, payload, phase) {
      received = { config, payload, phase }
      return '{"schema":1,"recorded":true}'
    },
  })
  await hook({
    ...event,
    status: "completed",
    result: { content: "SYNTHETIC_PHASE14_SECRET_CANARY" },
  })
  assert.equal(received.phase, "post-tool")
  assert.equal(received.payload.status, "completed")
  assert.equal(typeof received.payload.byte_size, "number")
  assert.equal(JSON.stringify(received.payload).includes("SYNTHETIC_PHASE14_SECRET_CANARY"), false)
})

test("passes a bounded canonical bridge payload and allows only valid allow", async () => {
  let received
  const hook = createToolHook({
    options,
    directory: "/workspace/project",
    run(config, payload) {
      received = { config, payload }
      return '{"schema":1,"decision":"allow"}'
    },
  })
  await hook(event)
  assert.equal(received.config.guard, options.guard)
  assert.deepEqual(received.payload, {
    schema: 1,
    session_id: "ses_test",
    call_id: "call_test",
    cwd: "/workspace/project",
    tool_name: "read",
    tool_input: { filePath: "README.md" },
  })
})

test("blocks deny, malformed output, execution failure, and invalid configuration", async () => {
  const outputs = [
    '{"schema":1,"decision":"deny","rule_id":"drupal.secret.env"}',
    '{"schema":1,"decision":"allow"',
  ]
  for (const output of outputs) {
    const hook = createToolHook({
      options,
      directory: "/workspace/project",
      run: () => output,
    })
    await assert.rejects(hook(event), /Blocked by team policy:/)
  }

  const failed = createToolHook({
    options,
    directory: "/workspace/project",
    run: () => {
      throw new Error("synthetic process failure")
    },
  })
  await assert.rejects(failed(event), /synthetic process failure/)

  const relative = createToolHook({
    options: { guard: "./daguard", policy: "./policy.json" },
    directory: "/workspace/project",
    run: () => '{"schema":1,"decision":"allow"}',
  })
  await assert.rejects(relative(event), /guard\.evaluation_error/)

  const missing = createToolHook({
    options: {
      guard: "/definitely/missing/daguard",
      policy: "/etc/daguard/policy.json",
    },
    directory: "/workspace/project",
  })
  await assert.rejects(missing(event), /guard\.evaluation_error/)
})

test("maps malformed deny rule IDs to the static evaluation error", async () => {
  const hook = createToolHook({
    options,
    directory: "/workspace/project",
    run: () =>
      '{"schema":1,"decision":"deny","rule_id":"unsafe\nmessage"}',
  })
  await assert.rejects(hook(event), /guard\.evaluation_error/)
})

test("passes managed mode to the bridge and rejects non-boolean values", async () => {
  let managed
  const hook = createToolHook({
    options: { ...options, managed: true },
    directory: "/workspace/project",
    run(config) { managed = config.managed; return '{"schema":1,"decision":"allow"}' },
  })
  await hook(event)
  assert.equal(managed, true)
  const invalid = createToolHook({
    options: { ...options, managed: "true" },
    directory: "/workspace/project",
  })
  await assert.rejects(invalid(event), /guard\.evaluation_error/)
})

test("validates an explicit persistent state directory for both bridge hooks", async () => {
  for (const create of [createToolHook, createPostToolHook]) {
    let received
    const hook = create({
      options: { ...options, stateDir: "/tmp/synthetic-state" },
      directory: "/workspace/project",
      run(config, payload, phase) {
        received = config
        return phase === "post-tool" ? '{"schema":1,"recorded":true}' : '{"schema":1,"decision":"allow"}'
      },
    })
    await hook({ ...event, status: "completed", result: "safe" })
    assert.equal(received.stateDir, "/tmp/synthetic-state")
    const invalid = create({
      options: { ...options, stateDir: "relative" },
      directory: "/workspace/project",
    })
    await assert.rejects(invalid({ ...event, status: "completed", result: "safe" }), /guard\.evaluation_error/)
  }
})
