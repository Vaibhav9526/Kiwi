# KIWI — Agent Handoff Log

> Owner: Lead Agent. Per prompt.md §9: any agent hitting a limit (quota,
> context, tool, crash, repeated error) must immediately make its task
> transferable by recording a handoff entry here.

## Handoff entry template

```
### HANDOFF <task-id> — <date> — from <agent>
- Task ID:
- Status at handoff:
- Completed work:
- Incomplete work:
- Modified files (exact paths):
- Tests run + results:
- Known failures:
- Assumptions:
- Next exact action:
- Suggested reassignment (per §9 capability map):
```

## Reassignment capability map (prompt.md §9)

- Thunderbird/core/security → Devin (Agent 1 or 2)
- forensics/protocol/testing → Cline DeepSeek (Agent 3)
- organization/admin/policy → Cline GLM (Agent 4)
- UI/UX → OpenCode Muse (Agent 5)
- QA/security verification → OpenCode Muse QA (Agent 6)

## Log

_(none yet)_
