# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# GolangElfLoader

## 技术栈
- **python**: 3.9+

## 核心运行命令
- python start.py
## start.py 自动扫描流程说明
start.py是项目中的核心自动化扫描脚本，负责基于输入的目标域名执行一系列信息收集和漏洞探测工作，流程主要包括：
./subfinder -dL url -all -t 200 -o log/passive.txt
puredns bruteforce file/config/subdomains.txt -d url -r file/config/resolvers.txt -q -w log/brute.txt
cat log/passive.txt log/brute.txt | sort -u > log/domain_life
puredns resolve log/domain_life -r file/config/resolvers.txt --wildcard-tests 50 --wildcard-batch 1000000 -q -w log/httpx_url
./httpx -l log/httpx_url -mc 200,301,302,403,404 -timeout 2 -favicon -hash md5,mmh3 -retries 1 -t 300 -rl 1000000 -resume -extract-fqdn -tls-grab -json -o log/result_all.json
python start.py
start.py具体做的事情你可以参考源码得知

## CRITICAL WORKFLOW - ALWAYS FOLLOW THIS!

### Research → Plan → Implement
**NEVER JUMP STRAIGHT TO CODING!** Always follow this sequence:
1. **Research**: Explore the codebase, understand existing patterns
2. **Plan**: Create a detailed implementation plan and verify it with me
3. **Implement**: Execute the plan with validation checkpoints

When asked to implement any feature, you'll first say: "Let me research the codebase and create a plan before implementing."

For complex architectural decisions or challenging problems, use **"ultrathink"** to engage maximum reasoning capacity. Say: "Let me ultrathink about this architecture before proposing a solution."

### USE MULTIPLE AGENTS!
*Leverage subagents aggressively* for better results:

* Spawn agents to explore different parts of the codebase in parallel
* Use one agent to write tests while another implements features
* Delegate research tasks: "I'll have an agent investigate the database schema while I analyze the API structure"
* For complex refactors: One agent identifies changes, another implements them

Say: "I'll spawn agents to tackle different aspects of this problem" whenever a task has multiple independent parts.

### Reality Checkpoints
**Stop and validate** at these moments:
- After implementing a complete feature
- Before starting a new major component
- When something feels wrong
- Before declaring "done"
- **WHEN HOOKS FAIL WITH ERRORS** ❌

Run: 编译当前golang项目的命令

> Why: You can lose track of what's actually working. These checkpoints prevent cascading failures.

### 🚨 CRITICAL: Hook Failures Are BLOCKING
**When hooks report ANY issues (exit code 2), you MUST:**
1. **STOP IMMEDIATELY** - Do not continue with other tasks
2. **FIX ALL ISSUES** - Address every ❌ issue until everything is ✅ GREEN
3. **VERIFY THE FIX** - Re-run the failed command to confirm it's fixed
4. **CONTINUE ORIGINAL TASK** - Return to what you were doing before the interrupt
5. **NEVER IGNORE** - There are NO warnings, only requirements

This includes:
- Formatting issues (gofmt, black, prettier, etc.)
- Linting violations (golangci-lint, eslint, etc.)
- Forbidden patterns (panic(), interface{})
- ALL other checks

Your code must be 100% clean. No exceptions.

**Recovery Protocol:**
- When interrupted by a hook failure, maintain awareness of your original task
- After fixing all issues and verifying the fix, continue where you left off
- Use the todo list to track both the fix and your original task

## 需求
1. 整体优化修改bug,并且给我这个项目一些渗透思路建议
2. 结合整个目录的构造来分析


## 关键约束条件


## Working Memory Management

### When context gets long:
- Re-read this CLAUDE.md file
- Summarize progress in a PROGRESS.md file
- Document current state before major changes

### 维护 TODO.md (你需要自己维护一个todo，来保证不会出现思维混乱的情况)

```
## Current Task
- [ ] What we're doing RIGHT NOW

## Completed  
- [x] What's actually done and tested

## Next Steps
- [ ] What comes next
```

## Problem-Solving Together

When you're stuck or confused:
1. **Stop** - Don't spiral into complex solutions
2. **Delegate** - Consider spawning agents for parallel investigation
3. **Ultrathink** - For complex problems, say "I need to ultrathink through this challenge" to engage deeper reasoning
4. **Step back** - Re-read the requirements
5. **Simplify** - The simple solution is usually correct
6. **Ask** - "I see two approaches: [A] vs [B]. Which do you prefer?"

My insights on better approaches are valued - please ask for them!
