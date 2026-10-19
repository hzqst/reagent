Verify the following reversed function against the decompiler output.

**Function:** ${class_name}::${function_name} at ${address}

**Reversed code:**
```cpp
${reversed_code}
```

**Decompiler output (derived evidence; may contain analysis errors):**
```
${decompiled}
```

**Proposed symbol (validate it; do not rewrite the code to fit it):**
${proposed_symbol}

**Source/header evidence collected by the harness (verify address and version correspondence):**
${source_context}

Check every line, offset, call, branch, and expression order. Return only the JSON object required by the system prompt.

Output constraint of the reverser (do not ask it to violate this):
- The candidate carries the target function plus optional helper types. A
  helper function may be added, but the harness needs exactly one definition
  whose head names the target; two definitions naming the same target are
  rejected.
- Prefer fixes that stay inside the target function. Do not demand a separate
  member/derived constructor definition when an inlined form preserves the
  same instructions; the target's own definition must remain present either way.
