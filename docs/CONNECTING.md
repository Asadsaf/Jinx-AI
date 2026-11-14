# Connecting Jinx to a target account (MCP · API · CLI)

Three ways to reach a GitHub-Copilot-style target, and every gotcha we hit doing it.
Rule that overrides everything: **the assistant never handles tokens or keys.** Any step
that types, reads, or stores a credential is done by a human. Jinx scores what it observes.

---

## 0. Which account am I acting as?
Half the wasted time in an engagement is "it refused" turning out to be "wrong account."
Before anything, pin down the identity on *each* channel — they are independent:
- **Browser (Claude in Chrome / your Chrome):** whoever is logged into github.com in that
  profile. Check the avatar, or `document.querySelector('meta[name="user-login"]').content`.
- **`gh` CLI:** `gh auth status` — often a *different* personal account than the lab org admin.
- **Copilot CLI:** logs the account on launch — grep `~/.copilot/logs/*` for
  `self-fetch complete for https://github.com/<login>`.
- **MCP github server:** acts as whatever PAT you put in its env.
These can all be four different identities at once. Make them match the account in scope.

---

## 1. MCP — the `github` server (best for scripted repo/issue/PR reads & writes)
```
claude mcp add github -- npx -y @modelcontextprotocol/server-github
```
Then give it a token **without the value ever touching the assistant**:
```
claude mcp remove github -s local
read -s "GH_PAT?Paste PAT: " && claude mcp add github -s local \
  -e GITHUB_PERSONAL_ACCESS_TOKEN="$GH_PAT" -- npx -y @modelcontextprotocol/server-github
unset GH_PAT
```
Gotchas we hit:
- **Run it in the project dir.** `-s local` config is per-folder; `claude mcp remove github`
  from the wrong directory says "No MCP server named github" while the real one sits elsewhere.
- **Lookalike `@`.** A pasted command turned `@modelcontextprotocol` into a full-width `＠`;
  npx then can't find the package. Retype the `@`.
- **New session to load it.** The current session won't see the server; start a fresh one.
- **`!`-prefixed input can't take a prompt.** `read -s` needs a real interactive shell, not the
  app's `!command` bar — run it in a terminal tab.
- **Token scope:** classic `repo` = read/write to every repo that account can reach. Prefer a
  fine-grained PAT limited to the lab repos. The token lands in `~/.claude.json` in plaintext.
- The deprecated `@modelcontextprotocol/server-github` still works; GitHub's newer
  `github/github-mcp-server` is the maintained replacement.

## 2. API — the model/inference endpoints
Useful as an *adversary* generator for `run_multiturn` or, rarely, as a bare target.
- **GitHub Models** (`https://models.github.ai/inference`) needs a GH token with the models
  scope. On a corporate/filtered network it may return a plain `OK`/200 to everything — that's
  a proxy intercept, not success. If a model never actually answers, suspect the network.
- A **bare model endpoint is a weak target**: no tools, no data = nothing to exfiltrate.
  Injection there is content-safety testing, not agent security. Usually mark N/A.
- Adversary key handling: put the **non-secret** bits (base_url, model) in a json file; put the
  **key** in the OS keychain and read it at runtime. Never write a key into a file or a command:
  ```
  security add-generic-password -a jinx -s jinx-adv-key -w     # user pastes the key
  # script reads it:  security find-generic-password -s jinx-adv-key -w
  ```

## 3. CLI — the vendor's own agent CLI (e.g. `@github/copilot`)
```
npm install -g @github/copilot        # official GitHub package
copilot login                         # device flow -> open the URL in the IN-SCOPE browser
```
Gotchas we hit, in order of how much time they cost:
- **It logs in as the wrong account.** `copilot login` opened against whatever browser profile
  was fronted / fell back to the `gh` login. Confirm with the `~/.copilot/logs` self-fetch line;
  `copilot logout && copilot login` and approve in the correct profile.
- **Org policy can block it.** "Access denied by policy settings … Your organization has
  restricted Copilot access" + "Third-party MCP servers are disabled by policy" means the org's
  Copilot policy forbids the CLI for that account. Different account or get the policy changed.
- **Non-interactive runs:** drive it with `copilot -p "<prompt>" --allow-tool view` (add
  `--allow-tool web_fetch` to let it fetch). Multi-turn: capture the `copilot --resume=<id>`
  line from stdout and pass `--resume <id>` next turn.
- **Capturing terminal bytes:** pipe loses TTY escapes; wrap in `script -q out.bin copilot -p …`
  to capture raw bytes (needed for ANSI/OSC escape findings).
- **Model routing is nondeterministic.** "Auto" picks different models per call; a finding may
  fire on one model (e.g. a fast variant) and not another. Log which model answered and run N
  times — report reliability as a fraction.

---

## 4. Which paid tiers gate what (verify, don't assume)
On a **Free** plan we confirmed, by trying:
- Reachable free: Copilot **Chat**, **CLI**, **Spaces**, and reading **Actions logs** via Chat.
- **Gated behind Copilot Pro:** the **coding agent** (Agents tab says "Upgrade"), **code review**
  (Copilot absent from a PR's reviewer list), **Autofix**, **Extensions**. These are the
  higher-impact (write/action) surfaces — note them and revisit if Pro is enabled.
Always verify availability by attempting the action, not by reading marketing pages.
