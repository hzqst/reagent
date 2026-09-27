# IDA type recovery acceptance fixture

This small Linux x64 binary contains a two-slot indirect dispatcher. It uses
untyped pointer arithmetic so IDA initially sees raw pointers/function pointers.
It is a synthetic fixture: it contains no proprietary binary or project types.

```sh
mkdir -p /tmp/re-agent-recovery
cc -O0 -fno-pie -no-pie -o /tmp/re-agent-recovery/fixture fixture.c
nm /tmp/re-agent-recovery/fixture | grep ' dispatch$'
```

Open the binary in a separate IDA instance with Hex-Rays and ida-pro-mcp enabled.
Use that instance's MCP URL in a temporary config with an independent `recovery`
provider/model. If using an idalib supervisor, connect to the dedicated worker's
MCP URL (printed when the worker starts), not the multi-database supervisor URL.
Do not use an unrelated working database for this acceptance exercise.

Run these commands with the dispatcher address reported by `nm`:

```sh
re-agent --config recovery.yaml recover-types --address ADDR --output preview.json
re-agent --config recovery.yaml recover-types --address ADDR --write --save --output write.json
```

The preview must not create types or change prototypes/locals. In write mode,
expect a class header with its vtable pointer at offset 0, a two-slot table with
slots at byte offsets 0 and 8, a typed object parameter and (if it survives
optimization) a typed vtable local. The precise inferred class/member names are
not fixed. The extra integer member is at offset 8; this is evidence of a partial
layout, not a general inference that every object has that complete size.

Inspect the report's tool results, backup path and independent checks. Close and
reopen the saved IDB and independently read the types/decompilation. Both virtual
calls should use named members with compatible signatures. Run recovery again:
equivalent types should be reused, without additional duplicate declarations.
A preview, a successful mock, or an agent's prose alone is not live acceptance.

## Recorded live acceptance (2026-09-27)

Tested against an actual ida-pro-mcp idalib worker with IDA 9.3 and Hex-Rays
9.3.0.260213, using this fixture compiled with GCC on Linux x64. The dispatcher
entry in that build was `0x401194`.

- A Pi/GLM preview investigated the untyped dispatcher without requesting writes.
- A Claude CLI/Sonnet run started with no `Op` or `Op_vt` types, created both,
  applied `Op *` to the object parameter, and explicitly persisted the surviving
  `vt` local as `Op_vt *` through the guarded recovery helper. Eight independent
  local/prototype/layout assertions passed, and `--save` succeeded.
- The saved IDB was copied and opened afresh; all eight assertions passed again.
  A separate saved-local inspection confirmed the local override persisted.
- Repeating the agent run against the reopened database verified the same facts
  with `write_attempted: false`; no duplicate types were created.

The resulting calls referenced `obj->vt->slot0` and `vt->slot1`. An integer-width
cast remained around the second named call; this test verifies object/vtable
pointer recovery and slot identity, not removal of every cosmetic cast. `Op`
was explicitly treated as a partial layout.

The exercise also exposed real integration cases now covered by regression
checks: IDA's property/method variants of `is_arg_var`, transient `server_health`
busy responses without database identity, absent saved-local records in the
stock MCP local setter, and the difference between a pseudocode instruction EA
and a local-variable definition EA. Failed or incomplete runs suppressed saving;
model-generated Python syntax is now checked before remote dispatch.
