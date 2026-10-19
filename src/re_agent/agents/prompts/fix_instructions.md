The checker found issues with your reversed code. Please fix all issues listed below.

**Checker Report:**
${checker_report}

**Issues to fix:**
${issues}

**Fix instructions:**
${fix_instructions}

Requirements:
- Fix ALL listed issues
- Do not introduce new problems
- Output the complete corrected function in a ```cpp block
  - Helper structs/classes/unions/enums may be defined above the function. Emit
    the target function definition; at most one extra helper function is
    allowed, and the target's definition head must name
    ${class_name}::${function_name} exactly once. Two definitions of the same
    target are rejected.
- End with: REVERSED_FUNCTION: ${class_name}::${function_name} (${address})
- If you proposed a symbol in the ```json block, emit it again — corrected if the
  checker disputed it, unchanged otherwise. Never invent a name to fill the field.
- If the symbol included a prototype, emit its declaration and evidence again
  only if still supported. Resolve prototype review notes; every new response
  receives a fresh independent review, even when its declaration is unchanged.
