import assert from "node:assert/strict"
import test from "node:test"

import plugin, { createToolHook } from "./index.js"

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
  let name
  let callback
  await plugin.setup({
    options,
    location: { directory: "/workspace/project" },
    tool: {
      async hook(value, handler) {
        name = value
        callback = handler
      },
    },
  })
  assert.equal(name, "execute.before")
  assert.equal(typeof callback, "function")
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
