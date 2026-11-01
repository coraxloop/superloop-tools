#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE_SCRIPT=${SIGNIN_TEST_BINARY:?the suite must bind the built lane fixture binary}
TEST_ROOT=$(mktemp -d "${TMPDIR:-$HOME/.cache/tmp}/loop-codex-home-tests.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
FAKE_HOME=$TEST_ROOT/home
FIXTURE_ROOT=$TEST_ROOT/tool
COPIED_BINARY=$FIXTURE_ROOT/bin/superloop-lane
SCRIPT=signin_home
signin_home() {
  local action=prepare-signin-home word
  local -a args=()
  for word in "$@"; do
    if [[ $word == --verify ]]; then action=check-signin-home; else args+=("$word"); fi
  done
  "$COPIED_BINARY" "$action" --backend codex "${args[@]}"
}
OUTSIDE=$TEST_ROOT/outside

fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

pass() {
  local name=$1 start=$2 end
  end=$(date +%s%N)
  printf 'PASS %s wall_ns=%s\n' "$name" "$((end - start))"
}

expect_line() {
  grep -Fqx -- "$2" "$1" || fail "$3"
}

mkdir -p "$FIXTURE_ROOT/bin" "$FAKE_HOME/.local/share/superloop-tools/loops.d" "$OUTSIDE" "$FAKE_HOME/dev/superloop-tools/loops.d" "$FAKE_HOME/.codex" "$FAKE_HOME/.local/share/orchestration-instance/docs/tools" "$FAKE_HOME/.config/loops/alpha/claude/keys" "$FAKE_HOME/.config/loops/beta/claude" "$FAKE_HOME/.config/loops/exact/claude" "$FAKE_HOME/.config/loops/ambiguous/claude" "$FAKE_HOME/.ssh" "$TEST_ROOT/project-derived" "$TEST_ROOT/project-beta-derived" "$TEST_ROOT/project-exact-derived" "$TEST_ROOT/project-ambiguous-derived"
cp "$SOURCE_SCRIPT" "$COPIED_BINARY"
chmod 700 "$FAKE_HOME"
chmod 700 "$FAKE_HOME/.config" "$FAKE_HOME/.config/loops" "$FAKE_HOME/.config/loops/alpha" "$FAKE_HOME/.config/loops/beta" "$FAKE_HOME/.config/loops/exact" "$FAKE_HOME/.config/loops/ambiguous"
chmod 700 "$COPIED_BINARY"
: > "$FAKE_HOME/.codex/auth.json"
: > "$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md"
: > "$FAKE_HOME/.ssh/superloop-alpha_ed25519"
ln -s "$FAKE_HOME/.ssh/superloop-alpha_ed25519" "$FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519"
chmod 700 "$FAKE_HOME/.local" "$FAKE_HOME/.local/share" "$FAKE_HOME/.local/share/superloop-tools" "$FAKE_HOME/.local/share/superloop-tools/loops.d"
cat > "$FAKE_HOME/.config/loops/registry.toml" <<EOF
namespace = 'org.superloop-tools.loophome.registry'
version = [1, 0, 0]
loops = [
  {name = 'alpha', uid = 2000, launch = 'src/alpha', session = 'alpha-session'},
  {name = 'gamma', uid = 41001, launch = 'src/gamma'},
  {name = 'epsilon', uid = 41002, launch = 'src/epsilon', session = 'epsilon-session'},
]
EOF
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/retired-project" > "$FAKE_HOME/dev/superloop-tools/loops.d/alpha.env"
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/project-derived" > "$FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env"
cat > "$FAKE_HOME/.config/loops/alpha/claude/ssh_config" <<EOF
Host node-a-alpha
  HostName 192.0.2.10
  Port 2201
  User alpha-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519

Host node-b-alpha
  HostName 192.0.2.20
  Port 2202
  User alpha-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519
EOF
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/project-beta-derived" > "$FAKE_HOME/.local/share/superloop-tools/loops.d/beta.env"
cat > "$FAKE_HOME/.config/loops/beta/claude/ssh_config" <<EOF
Host node-a-beta
  HostName 192.0.2.30
  Port 2251
  User derived-beta-account
  IdentityFile ~/.ssh/superloop-alpha_ed25519

Host node-b-beta
  HostName 192.0.2.40
  Port 2252
  User derived-beta-account
  IdentityFile ~/.ssh/superloop-alpha_ed25519
EOF
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/project-exact-derived" > "$FAKE_HOME/.local/share/superloop-tools/loops.d/exact.env"
cat > "$FAKE_HOME/.config/loops/exact/claude/ssh_config" <<EOF
Host node-a-exact
  HostName 198.51.100.60
  Port 2601
  User loop-specific-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519

Host node-a-worker
  HostName 192.0.2.60
  Port 2602
  User exact-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519

Host node-b-worker
  HostName 192.0.2.70
  Port 2701
  User exact-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519

Host node-b-exact
  HostName 198.51.100.70
  Port 2702
  User loop-specific-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519
EOF
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/project-ambiguous-derived" > "$FAKE_HOME/.local/share/superloop-tools/loops.d/ambiguous.env"
cat > "$FAKE_HOME/.config/loops/ambiguous/claude/ssh_config" <<EOF
Host node-a-first
  HostName 192.0.2.80
  Port 2801
  User ambiguous-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519

Host node-a-second
  HostName 192.0.2.81
  Port 2802
  User ambiguous-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519

Host node-b-worker
  HostName 192.0.2.90
  Port 2901
  User ambiguous-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519
EOF

# Registry facts are independent of the sibling SSH file, including ambiguous owner aliases.
mkdir -p "$FAKE_HOME/.local/share/orchestration-instance"
REGISTRY=$FAKE_HOME/.local/share/orchestration-instance/servers.md
cat > "$REGISTRY" <<EOF
## Node routes
|node|status|hostname|port|host_key_algorithm|host_key|loop|account|worker_alias|session_alias|worker_identity|session_identity|
|---|---|---|---|---|---|---|---|---|---|---|---|
|node-a|active|192.0.2.10|2201|ssh-ed25519|AAAA|alpha|alpha-account|node-a-worker|node-a-alpha|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-b|active|192.0.2.20|2202|ssh-ed25519|AAAA|alpha|alpha-account|node-b-worker|node-b-alpha|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-c|active|192.0.2.30|2203|ssh-ed25519|AAAA|alpha|alpha-account|node-c-worker|node-c-alpha|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|198.51.100.10|2301|ssh-ed25519|AAAA|beta|explicit-account|node-a-worker|node-a-beta|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-b|active|198.51.100.20|2302|ssh-ed25519|AAAA|beta|explicit-account|node-b-worker|node-b-beta|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|203.0.113.10|2401|ssh-ed25519|AAAA|gamma|gamma-account|node-a-worker|node-a-gamma|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-b|active|203.0.113.20|2402|ssh-ed25519|AAAA|gamma|gamma-account|node-b-worker|node-b-gamma|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|203.0.113.30|2501|ssh-ed25519|AAAA|epsilon|epsilon-account|node-a-worker|node-a-epsilon|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-b|active|203.0.113.40|2502|ssh-ed25519|AAAA|epsilon|epsilon-account|node-b-worker|node-b-epsilon|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|192.0.2.60|2602|ssh-ed25519|AAAA|exact|exact-account|node-a-worker|node-a-exact|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-b|active|192.0.2.70|2701|ssh-ed25519|AAAA|exact|exact-account|node-b-worker|node-b-exact|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|192.0.2.50|2451|ssh-ed25519|AAAA|delta|delta-account|node-a-worker|node-a-delta|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|192.0.2.80|2801|ssh-ed25519|AAAA|ambiguous|ambiguous-account|node-a-worker|node-a-ambiguous|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-b|active|192.0.2.90|2901|ssh-ed25519|AAAA|ambiguous|ambiguous-account|node-b-worker|node-b-ambiguous|$FAKE_HOME/.ssh/superloop-alpha_ed25519|~/.ssh/session-key|
|node-a|active|192.0.2.17|2217|ssh-ed25519|AAAA|repair|repair-account|node-a-worker|node-a-repair|$FAKE_HOME/.config/loops/repair/lanes/keys/worker-key|~/.ssh/session-key|
EOF

start=$(date +%s%N)
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha > "$TEST_ROOT/no-nodes.out" 2> "$TEST_ROOT/no-nodes.err")
status=$?
set -e
[[ $status -eq 2 ]] || fail "missing nodes exit was $status"
expect_line "$TEST_ROOT/no-nodes.err" 'superloop-lane signin-home: cannot resolve nodes; supply --nodes' "missing nodes reason"
[[ ! -e $FAKE_HOME/.config/loops/alpha/codex ]] || fail "missing nodes created home"
pass "missing node pair refuses by name" "$start"

start=$(date +%s%N)
for invalid_nodes in 'node-a,node-a' 'Node-a,node-b' 'node a,node-b' '' ',node-a' 'node-a,' 'node-a,,node-b' 'node-a,node-b,node-a' $'node-a\nnode-b'; do
  set +e
  (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes "$invalid_nodes" > "$TEST_ROOT/invalid-nodes.out" 2> "$TEST_ROOT/invalid-nodes.err")
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "invalid nodes $invalid_nodes exit was $status"
  [[ ! -s $TEST_ROOT/invalid-nodes.out ]] || fail "invalid nodes $invalid_nodes wrote stdout"
  expect_line "$TEST_ROOT/invalid-nodes.err" 'superloop-lane signin-home: invalid --nodes; expected one or more distinct node names' "invalid nodes $invalid_nodes reason"
  [[ ! -e $FAKE_HOME/.config/loops/alpha/codex ]] || fail "invalid nodes $invalid_nodes created home"
done
pass "invalid node lists refuse without writing a home" "$start"

start=$(date +%s%N)
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --verify > "$TEST_ROOT/verify-no-nodes.out" 2> "$TEST_ROOT/verify-no-nodes.err")
status=$?
set -e
[[ $status -eq 1 ]] || fail "verification without nodes exit was $status"
expect_line "$TEST_ROOT/verify-no-nodes.out" "{\"loop\":\"alpha\",\"home\":\"$FAKE_HOME/.config/loops/alpha/codex\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"nodes\",\"hosts\",\"user\",\"key\"],\"varied\":[],\"varied_lines\":[]}" "verification without nodes JSON"
[[ ! -s $TEST_ROOT/verify-no-nodes.err ]] || fail "verification without nodes wrote stderr"
[[ ! -e $FAKE_HOME/.config/loops/alpha/codex ]] || fail "verification without nodes created home"
pass "verification without nodes reports missing nodes" "$start"

start=$(date +%s%N)
charter=$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md
mv "$charter" "$TEST_ROOT/saved-charter.md"
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/no-charter.out" 2> "$TEST_ROOT/no-charter.err")
status=$?
set -e
[[ $status -ne 0 && ! -e $FAKE_HOME/.config/loops/alpha/codex ]] || fail "absent charter created home"
expect_line "$TEST_ROOT/no-charter.err" "superloop-lane signin-home: worker charter not found at $charter; pass --charter or install the instance publication" "missing charter refusal"
mv "$TEST_ROOT/saved-charter.md" "$charter"
pass "absent charter refuses before home creation" "$start"

start=$(date +%s%N)
if ! (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/create.out" 2> "$TEST_ROOT/create.err"); then
  fail "derived creation exited nonzero"
fi
HOME_DIR=$FAKE_HOME/.config/loops/alpha/codex
[[ $(stat -c '%a' -- "$HOME_DIR") == 700 ]] || fail "home mode"
[[ $(stat -c '%a' -- "$HOME_DIR/keys") == 700 ]] || fail "keys mode"
[[ $(stat -c '%a' -- "$HOME_DIR/config.toml") == 600 ]] || fail "config mode"
[[ $(stat -c '%a' -- "$HOME_DIR/ssh_config") == 600 ]] || fail "ssh config mode"
[[ ! -e $HOME_DIR/auth.json && ! -L $HOME_DIR/auth.json ]] || fail "creation placed sign-in"
[[ $(readlink -- "$HOME_DIR/AGENTS.md") == "$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md" ]] || fail "charter link target"
[[ $(readlink -- "$HOME_DIR/keys/superloop-alpha_ed25519") == "$FAKE_HOME/.ssh/superloop-alpha_ed25519" ]] || fail "key link target"
cat > "$TEST_ROOT/expected-config.toml" <<EOF
[sandbox_workspace_write]
network_access = true
# writable_roots: add the lane clone's .git per dispatch (the sandbox excludes .git from writable paths regardless of checkout shape)
writable_roots = []

[projects."$TEST_ROOT/project-derived"]
trust_level = "trusted"
EOF
cmp -s "$HOME_DIR/config.toml" "$TEST_ROOT/expected-config.toml" || fail "config differs from template of record"
cat > "$TEST_ROOT/expected-ssh-config" <<EOF
# Worker-server access for the alpha superloop's Codex lanes.
# Selected estate nodes; the brief scopes which alias a lane may use. Values
# selected from the instance routes registry (node-a,node-b);
# registry of record: ~/.local/share/orchestration-instance/servers.md. The key is the loop's own worker
# key, opening only the loop's own confined account.
Host node-a-worker
  HostName 192.0.2.10
  Port 2201
  User alpha-account
  IdentityFile $HOME_DIR/keys/superloop-alpha_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile $HOME_DIR/known_hosts.routes
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  UpdateHostKeys no

Host node-b-worker
  HostName 192.0.2.20
  Port 2202
  User alpha-account
  IdentityFile $HOME_DIR/keys/superloop-alpha_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile $HOME_DIR/known_hosts.routes
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  UpdateHostKeys no

EOF
cmp -s "$HOME_DIR/ssh_config" "$TEST_ROOT/expected-ssh-config" || fail "ssh config differs from template of record"
[[ $(tail -n 1 "$TEST_ROOT/create.out") == 'CODEX-HOME alpha READY' ]] || fail "ready marker"
probe_root=${TMPDIR:-$FAKE_HOME/.cache/tmp}
expect_line "$TEST_ROOT/create.err" "CODEX_HOME='$FAKE_HOME/.config/loops/alpha/lanes/codex' superloop-runtime exec -- exec -m MODEL -c model_reasoning_effort=EFFORT -C '$probe_root' --skip-git-repo-check -s read-only 'Reply with the single word OK.' < /dev/null" "owner probe"
pass "derived creation resolves symlinked key and matches templates" "$start"

start=$(date +%s%N)
config_before=$(cksum "$HOME_DIR/config.toml")
ssh_before=$(cksum "$HOME_DIR/ssh_config")
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/again.out" 2> "$TEST_ROOT/again.err")
status=$?
set -e
[[ $status -eq 3 ]] || fail "second creation exit was $status"
[[ ! -s $TEST_ROOT/again.out ]] || fail "second creation wrote stdout"
expect_line "$TEST_ROOT/again.err" "superloop-lane signin-home: home already exists: $HOME_DIR" "second creation reason"
[[ $(cksum "$HOME_DIR/config.toml") == "$config_before" ]] || fail "second creation changed config"
[[ $(cksum "$HOME_DIR/ssh_config") == "$ssh_before" ]] || fail "second creation changed ssh config"
pass "existing home refusal" "$start"

start=$(date +%s%N)
for sign_in in absent symlink hardlink dangling wrong-mode directory; do
  case $sign_in in
    symlink) ln -s "$FAKE_HOME/.codex/auth.json" "$HOME_DIR/auth.json" ;;
    hardlink) chmod 600 "$FAKE_HOME/.codex/auth.json"; ln "$FAKE_HOME/.codex/auth.json" "$HOME_DIR/auth.json" ;;
    dangling) ln -s "$TEST_ROOT/no-auth" "$HOME_DIR/auth.json" ;;
    wrong-mode) : > "$HOME_DIR/auth.json"; chmod 644 "$HOME_DIR/auth.json" ;;
    directory) mkdir "$HOME_DIR/auth.json" ;;
  esac
  set +e
  HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --verify > "$TEST_ROOT/sign-in.out" 2> "$TEST_ROOT/sign-in.err"
  status=$?
  set -e
  [[ $status -eq 1 ]] || fail "$sign_in sign-in verification exit $status"
  finding=sign-in
  [[ $sign_in != hardlink && $sign_in != wrong-mode ]] || finding=sign-in-link
  expect_line "$TEST_ROOT/sign-in.out" "{\"loop\":\"alpha\",\"home\":\"$HOME_DIR\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"$finding\"],\"varied\":[],\"varied_lines\":[]}" "$sign_in sign-in JSON"
  [[ ! -s $TEST_ROOT/sign-in.err ]] || fail "$sign_in sign-in stderr"
  if [[ $sign_in == directory ]]; then rmdir "$HOME_DIR/auth.json"; else rm -f "$HOME_DIR/auth.json"; fi
done
# Opaque fixture bytes: verification checks metadata, not credential contents.
CANONICAL=$FAKE_HOME/.config/loops/alpha/lanes/codex
mkdir -p "$CANONICAL"
chmod 700 "$FAKE_HOME" "$FAKE_HOME/.config" "$FAKE_HOME/.config/loops" "$FAKE_HOME/.config/loops/alpha" "$FAKE_HOME/.config/loops/alpha/lanes"
chmod 700 "$CANONICAL"
printf 'not-json\n' > "$CANONICAL/auth.json"
chmod 600 "$CANONICAL/auth.json"
HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/bind.out"
[[ $(readlink "$HOME_DIR/auth.json") == "$CANONICAL/auth.json" ]] || fail "canonical binding"
expect_line "$TEST_ROOT/bind.out" "CODEX-HOME alpha SIGN-IN-LINKED sign-in-link=$CANONICAL/auth.json" "existing home binding marker"
HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/bind-repeat.out"
cmp "$TEST_ROOT/bind.out" "$TEST_ROOT/bind-repeat.out" || fail "binding repeat"
chmod 640 "$CANONICAL/auth.json"
if HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --verify > "$TEST_ROOT/source.out" 2> "$TEST_ROOT/source.err"; then fail "unsafe canonical source accepted"; fi
expect_line "$TEST_ROOT/source.out" "{\"loop\":\"alpha\",\"home\":\"$HOME_DIR\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"sign-in-source\"],\"varied\":[],\"varied_lines\":[]}" "unsafe source finding"
chmod 600 "$CANONICAL/auth.json"
rm "$HOME_DIR/auth.json"
ln -s "$FAKE_HOME/.codex/auth.json" "$HOME_DIR/auth.json"
if HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/wrong-link.out" 2> "$TEST_ROOT/wrong-link.err"; then fail "wrong link overwritten"; fi
grep -q sign-in-link-conflict "$TEST_ROOT/wrong-link.err" || fail "named wrong-link conflict"
[[ $(readlink "$HOME_DIR/auth.json") == "$FAKE_HOME/.codex/auth.json" ]] || fail "wrong link not retained"
rm "$HOME_DIR/auth.json"
HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/bind.out"
chmod 750 "$HOME_DIR"
if HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/home-mode.out" 2> "$TEST_ROOT/home-mode.err"; then fail "unsafe existing home accepted"; fi
grep -q sign-in-home-owner-mode-type "$TEST_ROOT/home-mode.err" || fail "named home mode refusal"
chmod 700 "$HOME_DIR"
rm "$HOME_DIR/auth.json"
printf 'old synthetic login\n' > "$HOME_DIR/auth.json"
if HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/conflict.out" 2> "$TEST_ROOT/conflict.err"; then fail "regular credential overwritten"; fi
grep -q sign-in-link-conflict "$TEST_ROOT/conflict.err" || fail "named binding conflict"
expect_line "$HOME_DIR/auth.json" 'old synthetic login' "old credential retained"
rm "$HOME_DIR/auth.json"
HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b > "$TEST_ROOT/bind.out"
if ! (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --verify > "$TEST_ROOT/verify-ok.out" 2> "$TEST_ROOT/verify-ok.err"); then
  fail "complete verification exited nonzero"
fi
expect_line "$TEST_ROOT/verify-ok.out" "{\"loop\":\"alpha\",\"home\":\"$HOME_DIR\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":true,\"missing\":[],\"varied\":[],\"varied_lines\":[]}" "complete verification JSON"
[[ ! -s $TEST_ROOT/verify-ok.err ]] || fail "complete verification wrote stderr"
chmod 755 "$HOME_DIR/keys"
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --verify > "$TEST_ROOT/verify-mode.out" 2> "$TEST_ROOT/verify-mode.err")
status=$?
set -e
[[ $status -ne 0 ]] || fail "wrong keys mode verification exited zero"
expect_line "$TEST_ROOT/verify-mode.out" "{\"loop\":\"alpha\",\"home\":\"$HOME_DIR\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"keys-mode-700\"],\"varied\":[],\"varied_lines\":[]}" "keys mode verification JSON"
[[ ! -s $TEST_ROOT/verify-mode.err ]] || fail "keys mode verification wrote stderr"
chmod 700 "$HOME_DIR/keys"
# Older model defaults remain accepted and untouched; dispatch overrides them.
cp "$HOME_DIR/config.toml" "$TEST_ROOT/config-before"
printf '\nmodel = "gpt-5.6-sol"\nmodel_reasoning_effort = "xhigh"\n' > "$TEST_ROOT/old-models"
cat "$TEST_ROOT/old-models" "$TEST_ROOT/config-before" > "$HOME_DIR/config.toml"
old_config=$(cksum "$HOME_DIR/config.toml")
HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --verify > "$TEST_ROOT/verify-old.out"
[[ $(cksum "$HOME_DIR/config.toml") == "$old_config" ]] || fail "verification rewrote old defaults"
cp "$TEST_ROOT/config-before" "$HOME_DIR/config.toml"
mv "$HOME_DIR" "$TEST_ROOT/held-home"
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --verify > "$TEST_ROOT/verify-absent.out" 2> "$TEST_ROOT/verify-absent.err")
status=$?
set -e
[[ $status -ne 0 ]] || fail "absent home verification exited zero"
expect_line "$TEST_ROOT/verify-absent.out" "{\"loop\":\"alpha\",\"home\":\"$HOME_DIR\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"home\"],\"varied\":[],\"varied_lines\":[]}" "absent home verification JSON"
[[ ! -s $TEST_ROOT/verify-absent.err ]] || fail "absent home verification wrote stderr"
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" gamma --nodes node-a,node-b --home "$FAKE_HOME/.config/loops/gamma/codex" --user gamma-account --key "$FAKE_HOME/.ssh/superloop-alpha_ed25519" --hosts 'node-a:203.0.113.10:2401,node-b:203.0.113.20:2402' --verify > "$TEST_ROOT/verify-unresolved.out" 2> "$TEST_ROOT/verify-unresolved.err")
status=$?
set -e
[[ $status -eq 1 ]] || fail "unresolved verification exit was $status"
expect_line "$TEST_ROOT/verify-unresolved.out" "{\"loop\":\"gamma\",\"home\":\"$FAKE_HOME/.config/loops/gamma/codex\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"project: no LOOP_CWD in ~/.local/share/superloop-tools/loops.d/gamma.env\"],\"varied\":[],\"varied_lines\":[]}" "unresolved verification JSON"
[[ ! -s $TEST_ROOT/verify-unresolved.err ]] || fail "unresolved verification wrote stderr"
mv "$TEST_ROOT/held-home" "$HOME_DIR"
pass "read-only verification states" "$start"

start=$(date +%s%N)
if ! (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" exact --nodes node-a,node-b > "$TEST_ROOT/exact.out" 2> "$TEST_ROOT/exact.err"); then
  fail "exact alias creation exited nonzero"
fi
EXACT_HOME=$FAKE_HOME/.config/loops/exact/codex
expect_line "$EXACT_HOME/ssh_config" '  HostName 192.0.2.60' "exact node-a alias"
expect_line "$EXACT_HOME/ssh_config" '  Port 2602' "exact node-a port"
expect_line "$EXACT_HOME/ssh_config" '  HostName 192.0.2.70' "exact node-b alias"
expect_line "$EXACT_HOME/ssh_config" '  Port 2701' "exact node-b port"
expect_line "$EXACT_HOME/ssh_config" '  User exact-account' "exact alias user"
pass "exact worker aliases win over loop aliases" "$start"

start=$(date +%s%N)
EXPLICIT_HOME=$FAKE_HOME/.config/loops/beta/codex
EXPLICIT_KEY=$TEST_ROOT/explicit-key
EXPLICIT_PROJECT=$TEST_ROOT/project-explicit
: > "$EXPLICIT_KEY"
mkdir "$EXPLICIT_PROJECT"
if ! (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" beta --nodes node-a,node-b --home "$EXPLICIT_HOME" --claude-home "$FAKE_HOME/.config/loops/beta/claude" --user explicit-account --key "$EXPLICIT_KEY" --project "$EXPLICIT_PROJECT" --hosts 'node-a:198.51.100.10:2301,node-b:198.51.100.20:2302' > "$TEST_ROOT/explicit.out" 2> "$TEST_ROOT/explicit.err"); then
  fail "explicit creation exited nonzero"
fi
expect_line "$EXPLICIT_HOME/config.toml" "[projects.\"$EXPLICIT_PROJECT\"]" "explicit project"
expect_line "$EXPLICIT_HOME/ssh_config" '  HostName 198.51.100.10' "explicit node-a host"
expect_line "$EXPLICIT_HOME/ssh_config" '  Port 2301' "explicit node-a port"
expect_line "$EXPLICIT_HOME/ssh_config" '  HostName 198.51.100.20' "explicit node-b host"
expect_line "$EXPLICIT_HOME/ssh_config" '  Port 2302' "explicit node-b port"
expect_line "$EXPLICIT_HOME/ssh_config" '  User explicit-account' "explicit user"
[[ $(readlink -- "$EXPLICIT_HOME/keys/explicit-key") == "$EXPLICIT_KEY" ]] || fail "explicit key"
pass "explicit flags override derived sources" "$start"

start=$(date +%s%N)
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" gamma --nodes node-a,node-b --home "$TEST_ROOT/gamma-home" --user gamma-account --key "$EXPLICIT_KEY" --hosts 'node-a:203.0.113.10:2401,node-b:203.0.113.20:2402' > "$TEST_ROOT/unresolved.out" 2> "$TEST_ROOT/unresolved.err")
status=$?
set -e
[[ $status -eq 2 ]] || fail "unresolved project exit was $status"
[[ ! -e $TEST_ROOT/gamma-home ]] || fail "unresolved value created home"
[[ ! -s $TEST_ROOT/unresolved.out ]] || fail "unresolved value wrote stdout"
expect_line "$TEST_ROOT/unresolved.err" "superloop-lane signin-home: registry-record: gamma: no session id: $FAKE_HOME/.config/loops/registry.toml" "unresolved project reason"
pass "unresolvable value refusal" "$start"

start=$(date +%s%N)
printf 'LOOP_NAME=gamma\n' > "$FAKE_HOME/.local/share/superloop-tools/loops.d/gamma.env"
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" gamma --nodes node-a,node-b --home "$TEST_ROOT/gamma-home" --user gamma-account --key "$EXPLICIT_KEY" --hosts 'node-a:203.0.113.10:2401,node-b:203.0.113.20:2402' > "$TEST_ROOT/missing-project.out" 2> "$TEST_ROOT/missing-project.err")
status=$?
set -e
[[ $status -eq 2 ]] || fail "missing project exit was $status"
[[ ! -e $TEST_ROOT/gamma-home ]] || fail "missing project created home"
[[ ! -s $TEST_ROOT/missing-project.out ]] || fail "missing project wrote stdout"
printf '%s\n' 'superloop-lane signin-home: cannot resolve project; supply --project' > "$TEST_ROOT/missing-project.expected"
cmp "$TEST_ROOT/missing-project.expected" "$TEST_ROOT/missing-project.err" || fail "missing project reason"
rm "$FAKE_HOME/.local/share/superloop-tools/loops.d/gamma.env"
pass "existing record without project refuses creation without writes" "$start"

start=$(date +%s%N)
mkdir -p "$FAKE_HOME/.config/loops/delta/claude"
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/project-derived" > "$FAKE_HOME/.local/share/superloop-tools/loops.d/delta.env"
cat > "$FAKE_HOME/.config/loops/delta/claude/ssh_config" <<EOF
Host node-a-delta
  HostName 192.0.2.50
  Port 2451
  User delta-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519
EOF
set +e
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" delta --nodes node-a,node-b > "$TEST_ROOT/missing-stanza.out" 2> "$TEST_ROOT/missing-stanza.err")
status=$?
set -e
[[ $status -eq 2 ]] || fail "missing stanza exit was $status"
[[ ! -e $FAKE_HOME/.config/loops/delta/codex ]] || fail "missing stanza created home"
[[ ! -s $TEST_ROOT/missing-stanza.out ]] || fail "missing stanza wrote stdout"
expect_line "$TEST_ROOT/missing-stanza.err" 'superloop-lane signin-home: registry-node: node-b: no active row' "missing stanza reason"
pass "missing Claude ssh stanza refusal" "$start"

start=$(date +%s%N)
(cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" ambiguous --nodes node-a,node-b > "$TEST_ROOT/ambiguous.out" 2> "$TEST_ROOT/ambiguous.err") || fail "registry creation consulted ambiguous sibling aliases"
expect_line "$FAKE_HOME/.config/loops/ambiguous/codex/ssh_config" '  HostName 192.0.2.80' "registry endpoint"
pass "registry facts do not depend on ambiguous Claude aliases" "$start"

start=$(date +%s%N)
if [[ ${SIGNIN_TEST_FAULTS:-0} == 1 ]]; then
ATOMIC_HOME=$FAKE_HOME/.config/loops/epsilon/codex
set +e
(cd "$OUTSIDE" && SUPERLOOP_SIGNIN_TEST_CREATE_FAILURE=1 HOME=$FAKE_HOME "$SCRIPT" epsilon --nodes node-a,node-b --home "$ATOMIC_HOME" --user epsilon-account --key "$EXPLICIT_KEY" --project "$EXPLICIT_PROJECT" --hosts 'node-a:203.0.113.30:2501,node-b:203.0.113.40:2502' > "$TEST_ROOT/atomic.out" 2> "$TEST_ROOT/atomic.err")
status=$?
set -e
[[ $status -eq 2 ]] || fail "injected creation failure exit was $status"
[[ ! -e $ATOMIC_HOME && ! -L $ATOMIC_HOME ]] || fail "injected failure left final home"
shopt -s nullglob
leftovers=("$ATOMIC_HOME".new.*)
shopt -u nullglob
[[ ${#leftovers[@]} -eq 0 ]] || fail "injected failure left temporary home"
pass "failed creation leaves no partial home" "$start"
fi

start=$(date +%s%N)
cat >> "$FAKE_HOME/.config/loops/alpha/claude/ssh_config" <<EOF
Host node-c-worker
  HostName 192.0.2.30
  Port 2203
  User alpha-account
  IdentityFile $FAKE_HOME/.config/loops/alpha/claude/keys/superloop-alpha_ed25519
EOF
for node_list in node-a node-a,node-b,node-c; do
  list_home=$HOME_DIR
  rm -rf "$list_home"
  IFS=, read -r -a selected_nodes <<< "$node_list"
  (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes "$node_list" --home "$list_home" > "$TEST_ROOT/list.out" 2> "$TEST_ROOT/list.err") || fail "list $node_list creation"
  [[ $(readlink "$list_home/auth.json") == "$CANONICAL/auth.json" ]] || fail "new home canonical link"
  [[ $(grep -c '^Host ' "$list_home/ssh_config") -eq ${#selected_nodes[@]} ]] || fail "list $node_list stanza count"
  expect_line "$list_home/ssh_config" "# selected from the instance routes registry ($node_list);" "list comment"
  for node in "${selected_nodes[@]}"; do
    expect_line "$list_home/ssh_config" "Host $node-worker" "list alias $node"
  done
  (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes "$node_list" --home "$list_home" --verify > "$TEST_ROOT/list-verify.out" 2> "$TEST_ROOT/list-verify.err") || fail "list $node_list verification"
  expect_line "$TEST_ROOT/list-verify.out" "{\"loop\":\"alpha\",\"home\":\"$list_home\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":true,\"missing\":[],\"varied\":[],\"varied_lines\":[]}" "list verification JSON"
  [[ ! -s $TEST_ROOT/list-verify.err ]] || fail "list verification stderr"
done
pass "single and three-node derived creation and verification" "$start"

start=$(date +%s%N)
for node_list in node-a node-a,node-b node-a,node-b,node-c; do
  list_home=$HOME_DIR
  rm -rf "$list_home"
  host_list=node-a:192.0.2.10:2201
  [[ $node_list == node-a ]] || host_list=node-b:192.0.2.20:2202,$host_list
  [[ $node_list != node-a,node-b,node-c ]] || host_list=node-c:192.0.2.30:2203,$host_list
  (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes "$node_list" --home "$list_home" --hosts "$host_list" > "$TEST_ROOT/hosts.out" 2> "$TEST_ROOT/hosts.err") || fail "hosts $node_list creation"
  [[ $(readlink "$list_home/auth.json") == "$CANONICAL/auth.json" ]] || fail "new home canonical link"
  expect_line "$list_home/ssh_config" '  HostName 192.0.2.10' "label-based host mapping"
  (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes "$node_list" --home "$list_home" --hosts "$host_list" --verify > "$TEST_ROOT/hosts-verify.out" 2> "$TEST_ROOT/hosts-verify.err") || fail "hosts $node_list verification"
  expect_line "$TEST_ROOT/hosts-verify.out" "{\"loop\":\"alpha\",\"home\":\"$list_home\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":true,\"missing\":[],\"varied\":[],\"varied_lines\":[]}" "hosts verification JSON"
done
pass "host labels match in any order for one two and three nodes" "$start"

start=$(date +%s%N)
for invalid_hosts in 'node-a:192.0.2.10:2201' 'node-a:192.0.2.10:2201,node-b:192.0.2.20:2202,node-c:192.0.2.30:2203' 'node-a:192.0.2.10:2201,node-c:192.0.2.30:2203' 'node-a:192.0.2.10:2201,node-a:192.0.2.20:2202' 'node-a:192.0.2.10:2201,node-b:192.0.2.20:2202,'; do
  set +e
  (cd "$OUTSIDE" && HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --home "$TEST_ROOT/invalid-hosts-home" --hosts "$invalid_hosts" > "$TEST_ROOT/invalid-hosts.out" 2> "$TEST_ROOT/invalid-hosts.err")
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "invalid hosts exit was $status"
  [[ ! -s $TEST_ROOT/invalid-hosts.out && ! -e $TEST_ROOT/invalid-hosts-home ]] || fail "invalid hosts wrote home or stdout"
  grep -Fq "registry-node:" "$TEST_ROOT/invalid-hosts.err" || fail "invalid hosts reason"
  grep -Fq -- "--hosts" "$TEST_ROOT/invalid-hosts.err" || fail "invalid hosts flag detail"
done
pass "host count duplicate and unlisted labels refuse" "$start"

start=$(date +%s%N)
# Reconcile a separately built two-node home; include unrelated SSH content and
# credential/project/key fixtures so both the no-write and preservation claims
# cover more than the rewritten stanzas.
RECONCILE_HOME=$HOME_DIR
rm -rf "$RECONCILE_HOME"
RECONCILE_CLAUDE=$TEST_ROOT/reconcile-claude
mkdir "$RECONCILE_CLAUDE"
chmod 700 "$RECONCILE_CLAUDE"
cp "$FAKE_HOME/.config/loops/alpha/claude/ssh_config" "$RECONCILE_CLAUDE/ssh_config"
sed -i -e 's/^Host node-b-alpha$/Host node-b-worker/' -e '/^Host node-c-worker/i # Keep this comment between node-b and node-c.' "$RECONCILE_CLAUDE/ssh_config"
HOME=$FAKE_HOME "$SCRIPT" alpha --nodes node-a,node-b --home "$RECONCILE_HOME" --claude-home "$RECONCILE_CLAUDE" > "$TEST_ROOT/reconcile-create.out" 2> "$TEST_ROOT/reconcile-create.err"
printf 'opaque codex sign-in\n' > "$RECONCILE_HOME/auth.json"
chmod 600 "$RECONCILE_HOME/auth.json"
printf 'opaque claude sign-in\n' > "$RECONCILE_CLAUDE/.credentials.json"
mkdir "$RECONCILE_CLAUDE/projects"
printf 'project transcript\n' > "$RECONCILE_CLAUDE/projects/transcript"
for ssh_file in "$RECONCILE_HOME/ssh_config" "$RECONCILE_CLAUDE/ssh_config"; do
  cat >> "$ssh_file" <<'EOF'
Host unrelated
  HostName unrelated.invalid
  ServerAliveInterval 17
EOF
done

snapshot() {
  python3 - "${1:-$RECONCILE_HOME}" "${2:-$RECONCILE_CLAUDE}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

rows = []
for root in map(Path, sys.argv[1:]):
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        value = (str(path.readlink()) if path.is_symlink() else
                 hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else '')
        rows.append((str(path), info.st_mode, info.st_ino, info.st_mtime_ns, value))
print(json.dumps(rows))
PY
}

reconcile_home() {
  HOME=$FAKE_HOME "$SCRIPT" alpha --home "$RECONCILE_HOME" --claude-home "$RECONCILE_CLAUDE" "$@"
}

digest_from() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["digest"])' "$1"
}

start=$(date +%s%N)
REPAIR_HOME=$FAKE_HOME/.config/loops/repair/codex
REPAIR_CLAUDE=$FAKE_HOME/.config/loops/repair/claude
mkdir -p "$REPAIR_HOME/keys" "$REPAIR_CLAUDE"
chmod 700 "$FAKE_HOME/.config/loops/repair" "$REPAIR_HOME" "$REPAIR_HOME/keys" "$REPAIR_CLAUDE"
printf 'LOOP_CWD=%s\n' "$TEST_ROOT/project-derived" > "$FAKE_HOME/.local/share/superloop-tools/loops.d/repair.env"
printf 'opaque fixture worker key\n' > "$REPAIR_HOME/keys/worker-key"
chmod 600 "$REPAIR_HOME/keys/worker-key"
key_inode=$(stat -c '%i' "$REPAIR_HOME/keys/worker-key")
printf 'model = "owner-model"\n' > "$REPAIR_HOME/config.toml"
printf '[sandbox_workspace_write]\n# owner dispatch roots\nwritable_roots = ["%s/.git"]\n' "$TEST_ROOT/fixture-clone" >> "$REPAIR_HOME/config.toml"
cp "$REPAIR_HOME/config.toml" "$TEST_ROOT/repair-owner-config"
cat > "$TEST_ROOT/repair-loop-stanza" <<'EOF'
Host node-a-repair
  HostName owner.invalid
  User owner-account
  ServerAliveInterval 19

EOF
cp "$TEST_ROOT/repair-loop-stanza" "$REPAIR_HOME/ssh_config"
cat >> "$REPAIR_HOME/ssh_config" <<EOF
Host node-a-worker
  HostName 192.0.2.17
  Port 2217
  User repair-account
  IdentityFile $REPAIR_HOME/keys/worker-key
EOF
cp "$REPAIR_HOME/ssh_config" "$REPAIR_CLAUDE/ssh_config"
chmod 600 "$REPAIR_HOME/config.toml" "$REPAIR_HOME/ssh_config" "$REPAIR_CLAUDE/ssh_config"
repair_home() {
  HOME=$FAKE_HOME "$SCRIPT" repair --nodes node-a "$@"
}
mv "$REPAIR_HOME/keys/worker-key" "$TEST_ROOT/repair-external-key"
chmod 000 "$TEST_ROOT/repair-external-key"
ln -s "$TEST_ROOT/repair-external-key" "$REPAIR_HOME/keys/worker-key"
for key_state in live dangling; do
  if [[ $key_state == dangling ]]; then
    mv "$TEST_ROOT/repair-external-key" "$TEST_ROOT/repair-saved-key"
  fi
  for key_route in inferred explicit; do
    key_args=()
    if [[ $key_route == explicit ]]; then
      key_args=(--key "$REPAIR_HOME/keys/worker-key")
    fi
    before=$(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE")
    if repair_home --repair --dry-run "${key_args[@]}" > "$TEST_ROOT/repair-link.out" 2> "$TEST_ROOT/repair-link.err"; then
      fail "repair accepted $key_state linked key via $key_route"
    fi
    [[ ! -s $TEST_ROOT/repair-link.out ]] || fail "linked key refusal printed a plan"
    grep -Fq "codex-repair-key: $REPAIR_HOME/keys/worker-key is a link to $(readlink "$REPAIR_HOME/keys/worker-key"); move the key file into lanes/keys/ by rename and relink, then repair" "$TEST_ROOT/repair-link.err" || fail "linked key refusal lost entry or target"
    [[ $(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE") == "$before" ]] || fail "linked key refusal wrote home"
  done
done
rm "$REPAIR_HOME/keys/worker-key"
for key_route in inferred explicit; do
  key_args=()
  [[ $key_route != explicit ]] || key_args=(--key "$REPAIR_HOME/keys/worker-key")
  before=$(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE")
  if repair_home --repair --dry-run "${key_args[@]}" > "$TEST_ROOT/repair-missing.out" 2> "$TEST_ROOT/repair-missing.err"; then
    fail "repair accepted missing key via $key_route"
  fi
  [[ ! -s $TEST_ROOT/repair-missing.out ]] || fail "missing key refusal printed a plan"
  grep -Fq 'cannot resolve key; supply --key' "$TEST_ROOT/repair-missing.err" || fail "missing key refusal lost remedy"
  [[ $(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE") == "$before" ]] || fail "missing key refusal wrote home"
done
mv "$TEST_ROOT/repair-saved-key" "$REPAIR_HOME/keys/worker-key"
chmod 600 "$REPAIR_HOME/keys/worker-key"
before=$(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE")
repair_home --repair --dry-run > "$TEST_ROOT/repair-plan.out"
[[ $(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE") == "$before" ]] || fail "repair preview wrote home"
digest=$(digest_from "$TEST_ROOT/repair-plan.out")
if repair_home --repair --expect-digest "${digest//?/0}" > "$TEST_ROOT/repair-wrong.out" 2> "$TEST_ROOT/repair-wrong.err"; then
  fail "repair accepted wrong digest"
fi
[[ $(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE") == "$before" ]] || fail "wrong repair digest wrote home"
python3 - "$COPIED_BINARY" "$FAKE_HOME" "$REPAIR_HOME" "$digest" <<'PY'
import fcntl, os, subprocess, sys
binary, owner, home, digest = sys.argv[1:]
fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
fcntl.flock(fd, fcntl.LOCK_SH)
result = subprocess.run([binary, 'prepare-signin-home', '--backend', 'codex', 'repair', '--nodes', 'node-a', '--repair', '--expect-digest', digest], env=dict(os.environ, HOME=owner), capture_output=True, text=True, timeout=15)
assert result.returncode == 2, result
assert not result.stdout, result.stdout
assert f'codex-home-locked: {home}' in result.stderr, result.stderr
os.close(fd)
PY
[[ $(snapshot "$REPAIR_HOME" "$REPAIR_CLAUDE") == "$before" ]] || fail "locked repair wrote home"
repair_home --repair --expect-digest "$digest" > "$TEST_ROOT/repair-apply.out"
repair_home --repair --dry-run > "$TEST_ROOT/repair-again.out"
repair_home --repair --dry-run --key "$REPAIR_HOME/keys/worker-key" > "$TEST_ROOT/repair-explicit-again.out"
python3 - "$TEST_ROOT/repair-plan.out" "$REPAIR_HOME/config.toml" "$TEST_ROOT/repair-owner-config" <<'PY'
import json, pathlib, sys
plan = json.loads(pathlib.Path(sys.argv[1]).read_text())['plan']
config = next(file for file in plan['files'] if file['path'].endswith('/config.toml'))
assert config['writable_roots'] == {'owner_line_kept': True, 'roots': 1}
assert len(config['skipped_comment_lines']) == 1
before = pathlib.Path(sys.argv[3]).read_bytes()
after = pathlib.Path(sys.argv[2]).read_bytes()
assert after.startswith(before), (before, after)
assert config['before'].encode() == before
assert config['after'].encode() == after
assert [line for line in after.splitlines() if line.startswith(b'#')] == [b'# owner dispatch roots']
PY
python3 - "$TEST_ROOT/repair-again.out" "$REPAIR_HOME/ssh_config" "$TEST_ROOT/repair-loop-stanza" "$TEST_ROOT/repair-explicit-again.out" <<'PY'
import json, pathlib, sys
assert json.loads(pathlib.Path(sys.argv[1]).read_text())['changed'] == 0
assert json.loads(pathlib.Path(sys.argv[4]).read_text())['changed'] == 0
ssh = pathlib.Path(sys.argv[2]).read_bytes()
assert pathlib.Path(sys.argv[3]).read_bytes() in ssh
assert ssh.count(b'# selected from the instance routes registry (node-a);') == 1
PY
expect_line "$REPAIR_HOME/config.toml" 'model = "owner-model"' "repair owner config"
[[ $(readlink "$REPAIR_HOME/keys/worker-key") == "$FAKE_HOME/.config/loops/repair/lanes/keys/worker-key" ]] || fail "repair key target"
[[ $(stat -c '%i' "$FAKE_HOME/.config/loops/repair/lanes/keys/worker-key") == "$key_inode" ]] || fail "repair copied key instead of rename"
[[ -L $REPAIR_HOME/AGENTS.md && -L $REPAIR_HOME/auth.json ]] || fail "repair links absent"
repair_home --reconcile --dry-run > "$TEST_ROOT/repair-reconcile.out"
python3 -c 'import json, sys; assert json.load(open(sys.argv[1]))["changed"] == 0' "$TEST_ROOT/repair-reconcile.out" || fail "repaired home changed on reconcile"
pass "legacy Codex repair digest lock rename preservation and reconcile" "$start"

start=$(date +%s%N)
before=$(snapshot)
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/reconcile-plan.out"
[[ $(snapshot) == "$before" ]] || fail "reconcile dry run wrote home"
digest=$(digest_from "$TEST_ROOT/reconcile-plan.out")
[[ $digest =~ ^[0-9a-f]{64}$ ]] || fail "reconcile plan digest"
set +e
reconcile_home --nodes node-a --reconcile --expect-digest "${digest//?/0}" > "$TEST_ROOT/reconcile-mismatch.out" 2> "$TEST_ROOT/reconcile-mismatch.err"
status=$?
set -e
[[ $status -eq 2 ]] || fail "reconcile mismatch exit $status"
[[ ! -s $TEST_ROOT/reconcile-mismatch.out ]] || fail "reconcile mismatch printed success or plan"
[[ $(snapshot) == "$before" ]] || fail "reconcile mismatch wrote home"
expect_line "$TEST_ROOT/reconcile-mismatch.err" 'superloop-lane signin-home: reconcile digest mismatch; repeat --dry-run' "reconcile mismatch reason"
# A formerly valid digest must also refuse if either input changed.
printf '# changed after preview\n' >> "$RECONCILE_CLAUDE/ssh_config"
before=$(snapshot)
set +e
reconcile_home --nodes node-a --reconcile --expect-digest "$digest" > "$TEST_ROOT/reconcile-stale.out" 2> "$TEST_ROOT/reconcile-stale.err"
status=$?
set -e
[[ $status -eq 2 && $(snapshot) == "$before" ]] || fail "stale reconcile did not refuse without writes"
[[ ! -s $TEST_ROOT/reconcile-stale.out ]] || fail "stale reconcile printed success or plan"
pass "reconcile preview and mismatching or stale digest never write" "$start"

start=$(date +%s%N)
protected_before=$(cksum "$RECONCILE_HOME/config.toml" "$RECONCILE_HOME/auth.json" "$RECONCILE_CLAUDE/.credentials.json" "$RECONCILE_CLAUDE/projects/transcript")
key_before=$(readlink "$RECONCILE_HOME/keys/superloop-alpha_ed25519")
charter_before=$(readlink "$RECONCILE_HOME/AGENTS.md")
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/reconcile-plan.out"
digest=$(digest_from "$TEST_ROOT/reconcile-plan.out")
reconcile_home --nodes node-a --reconcile --expect-digest "$digest" > "$TEST_ROOT/reconcile-apply.out"
expect_line "$TEST_ROOT/reconcile-apply.out" "{\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"digest\":\"$digest\",\"outcome\":\"applied\",\"replaced\":3}" "reconcile completion result"
for ssh_file in "$RECONCILE_HOME/ssh_config" "$RECONCILE_CLAUDE/ssh_config"; do
  ! grep -q '^Host node-b-' "$ssh_file" || fail "reconcile kept removed node"
  expect_line "$ssh_file" 'Host unrelated' "unrelated alias preserved"
  expect_line "$ssh_file" '  ServerAliveInterval 17' "unrelated option preserved"
done
[[ $(grep -c '^Host ' "$RECONCILE_HOME/ssh_config") -eq 2 ]] || fail "Codex stanza count"
[[ $(grep -c '^Host ' "$RECONCILE_CLAUDE/ssh_config") -eq 3 ]] || fail "Claude stanza count"
expect_line "$RECONCILE_CLAUDE/ssh_config" 'Host node-c-worker' "unselected unowned node preserved"
expect_line "$RECONCILE_CLAUDE/ssh_config" '# Keep this comment between node-b and node-c.' "inter-stanza comment preserved"
expect_line "$RECONCILE_CLAUDE/ssh_config" 'Host node-a-alpha' "retained Claude alias"
[[ $(cksum "$RECONCILE_HOME/config.toml" "$RECONCILE_HOME/auth.json" "$RECONCILE_CLAUDE/.credentials.json" "$RECONCILE_CLAUDE/projects/transcript") == "$protected_before" ]] || fail "reconcile changed protected files"
[[ $(readlink "$RECONCILE_HOME/keys/superloop-alpha_ed25519") == "$key_before" ]] || fail "reconcile changed key link"
[[ $(readlink "$RECONCILE_HOME/AGENTS.md") == "$charter_before" ]] || fail "reconcile changed charter link"
reconcile_home --nodes node-a --verify > "$TEST_ROOT/reconcile-verify.out"
expect_line "$TEST_ROOT/reconcile-verify.out" "{\"loop\":\"alpha\",\"home\":\"$RECONCILE_HOME\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":true,\"missing\":[],\"varied\":[],\"varied_lines\":[]}" "reconciled verification"
pass "two-node home reconciles to one and preserves non-node state" "$start"

start=$(date +%s%N)
before=$(snapshot)
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/reconcile-noop.out"
python3 -c 'import json, sys; assert json.load(open(sys.argv[1]))["changed"] == 0' "$TEST_ROOT/reconcile-noop.out" || fail "unchanged plan changed count"
digest=$(digest_from "$TEST_ROOT/reconcile-noop.out")
reconcile_home --nodes node-a --reconcile --expect-digest "$digest" > "$TEST_ROOT/reconcile-noop-apply.out"
expect_line "$TEST_ROOT/reconcile-noop-apply.out" "{\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"digest\":\"$digest\",\"outcome\":\"applied\",\"replaced\":0}" "no-op completion result"
[[ $(snapshot) == "$before" ]] || fail "unchanged reconcile wrote home"
# Existing records do not require configuration lookup.
mv "$FAKE_HOME/.config/loops/registry.toml" "$TEST_ROOT/registry.toml"
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/reconcile-without-config.out"
cmp "$TEST_ROOT/reconcile-noop.out" "$TEST_ROOT/reconcile-without-config.out" || fail "existing record looked up configuration"
mv "$TEST_ROOT/registry.toml" "$FAKE_HOME/.config/loops/registry.toml"
pass "unchanged reconciliation reports changed zero and writes nothing" "$start"

start=$(date +%s%N)
# An absent record is planned without writes and created only on digest-approved apply.
mv "$FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env" "$TEST_ROOT/alpha.env"
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/reconcile-no-project.out"
[[ ! -e $FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env ]] || fail "preview wrote record"
python3 - "$TEST_ROOT/reconcile-no-project.out" "$FAKE_HOME" "$TEST_ROOT/reconcile-record.expected" <<'PYRECORD'
import json, sys
report = json.load(open(sys.argv[1]))
owner = sys.argv[2]
assert report['changed'] == 1
assert report['plan']['files'][-1] == {
    'path': owner + '/.local/share/superloop-tools/loops.d/alpha.env',
    'mode': 384, 'before': None, 'action': 'write',
    'after': f'LOOP_NAME=alpha\nLOOP_SID=alpha-session\nLOOP_CWD={owner}/src/alpha\nLOOP_UID=2000\nLOOP_HOME={owner}/.var/loops/alpha\n',
}
with open(sys.argv[3], 'wb') as expected:
    expected.write(report['plan']['files'][-1]['after'].encode('utf-8'))
PYRECORD
digest=$(digest_from "$TEST_ROOT/reconcile-no-project.out")
reconcile_home --nodes node-a --reconcile --expect-digest "$digest" > "$TEST_ROOT/reconcile-record-apply.out"
expect_line "$TEST_ROOT/reconcile-record-apply.out" "{\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"digest\":\"$digest\",\"outcome\":\"applied\",\"replaced\":1}" "record completion result"
cmp "$TEST_ROOT/reconcile-record.expected" "$FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env" || fail "applied record differs from preview"
[[ $(stat -c '%a' "$FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env") == 600 ]] || fail "record mode"
expect_line "$FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env" 'LOOP_SID=alpha-session' "record session"
mv "$TEST_ROOT/alpha.env" "$FAKE_HOME/.local/share/superloop-tools/loops.d/alpha.env"
pass "absent record reconciliation applies one replacement matching preview bytes" "$start"

start=$(date +%s%N)
printf '  ServerAliveInterval 23\n' >> "$RECONCILE_HOME/ssh_config"
# Endpoints change only by editing the registry; --hosts must agree.
sed -i -e 's/|192.0.2.10|2201|/|198.51.100.90|2290|/' -e 's/|192.0.2.20|2202|/|198.51.100.91|2291|/' "$REGISTRY"
options=(--nodes node-a,node-b --hosts node-a:198.51.100.90:2290,node-b:198.51.100.91:2291 --user alpha-account --key "$FAKE_HOME/.ssh/superloop-alpha_ed25519" --reconcile)
modes_before=$(stat -c '%a' "$RECONCILE_HOME/ssh_config" "$RECONCILE_CLAUDE/ssh_config")
reconcile_home "${options[@]}" --dry-run > "$TEST_ROOT/reconcile-add.out"
digest=$(digest_from "$TEST_ROOT/reconcile-add.out")
reconcile_home "${options[@]}" --expect-digest "$digest" > "$TEST_ROOT/reconcile-add-apply.out"
for ssh_file in "$RECONCILE_HOME/ssh_config" "$RECONCILE_CLAUDE/ssh_config"; do
  expect_line "$ssh_file" '  HostName 198.51.100.90' "updated endpoint"
  expect_line "$ssh_file" 'Host node-b-worker' "new node alias"
  expect_line "$ssh_file" '  Port 2291' "new node port"
done
[[ $(stat -c '%a' "$RECONCILE_HOME/ssh_config" "$RECONCILE_CLAUDE/ssh_config") == "$modes_before" ]] || fail "reconcile changed SSH modes"
[[ $(cksum "$RECONCILE_HOME/config.toml" "$RECONCILE_HOME/auth.json" "$RECONCILE_CLAUDE/.credentials.json" "$RECONCILE_CLAUDE/projects/transcript") == "$protected_before" ]] || fail "adding nodes changed protected files"
reconcile_home --nodes node-a,node-b --verify > "$TEST_ROOT/reconcile-add-verify.out" || {
  cat "$TEST_ROOT/reconcile-add-verify.out" >&2
  fail "verification after adding a node"
}
reconcile_home --nodes node-a,node-b --reconcile --dry-run > "$TEST_ROOT/reconcile-added-noop.out"
python3 -c 'import json, sys; assert json.load(open(sys.argv[1]))["changed"] == 0' "$TEST_ROOT/reconcile-added-noop.out" || fail "added-node plan not stable"
before=$(snapshot)
pass "reconcile updates endpoints and adds nodes with the existing key" "$start"

start=$(date +%s%N)
# Only exact worker aliases are owned, including for removed nodes.
EXACT_CLAUDE=$FAKE_HOME/.config/loops/exact/claude
chmod 700 "$EXACT_CLAUDE"
python3 - "$EXACT_CLAUDE/ssh_config" "$EXACT_HOME/ssh_config" "$TEST_ROOT/exact-sessions" <<'PY'
from pathlib import Path
import re, sys
claude, codex, saved = map(Path, sys.argv[1:])
blocks = re.split(r'(?m)(?=^Host )', claude.read_text())
sessions = ''.join(b for b in blocks if b.startswith(('Host node-a-exact\n', 'Host node-b-exact\n')))
assert sessions.count('Host ') == 2
saved.write_text(sessions)
with codex.open('a') as f:
    f.write(sessions)
PY
sed -i 's/|192.0.2.60|2602|/|198.51.100.99|2299|/' "$REGISTRY"
exact_before=$(snapshot "$EXACT_HOME" "$EXACT_CLAUDE")
HOME=$FAKE_HOME "$SCRIPT" exact --nodes node-a --hosts node-a:198.51.100.99:2299 --reconcile --dry-run > "$TEST_ROOT/exact-reconcile.out"
[[ $(snapshot "$EXACT_HOME" "$EXACT_CLAUDE") == "$exact_before" ]] || fail "exact preview changed home"
python3 - "$TEST_ROOT/exact-reconcile.out" "$TEST_ROOT/exact-sessions" <<'PYPLAN'
from pathlib import Path
import json, re, sys
expected = Path(sys.argv[2]).read_bytes()
for file in json.loads(Path(sys.argv[1]).read_text())['plan']['files']:
    if not file['path'].endswith('/ssh_config'): continue
    blocks = re.split(rb'(?m)(?=^Host )', file['after'].encode())
    sessions = b''.join(b for b in blocks if b.startswith((b'Host node-a-exact\n', b'Host node-b-exact\n')))
    assert sessions == expected, file['path']
PYPLAN
digest=$(digest_from "$TEST_ROOT/exact-reconcile.out")
HOME=$FAKE_HOME "$SCRIPT" exact --nodes node-a --hosts node-a:198.51.100.99:2299 --reconcile --expect-digest "$digest" > "$TEST_ROOT/exact-reconcile-apply.out"
python3 - "$EXACT_CLAUDE/ssh_config" "$EXACT_HOME/ssh_config" "$TEST_ROOT/exact-sessions" <<'PY'
from pathlib import Path
import re, sys
expected = Path(sys.argv[3]).read_bytes()
for name in sys.argv[1:3]:
    blocks = re.split(rb'(?m)(?=^Host )', Path(name).read_bytes())
    sessions = b''.join(b for b in blocks if b.startswith((b'Host node-a-exact\n', b'Host node-b-exact\n')))
    assert sessions == expected, name
    worker = [b for b in blocks if b.startswith(b'Host node-a-worker\n')]
    assert len(worker) == 1 and b'  HostName 198.51.100.99\n' in worker[0], name
    assert not any(b.startswith(b'Host node-b-worker\n') for b in blocks), name
PY
pass "selected and removed nodes preserve loop stanzas byte-identical and reconcile only exact workers" "$start"

start=$(date +%s%N)
for ssh_file in "$EXACT_HOME/ssh_config" "$EXACT_CLAUDE/ssh_config"; do
  cp "$ssh_file" "$TEST_ROOT/exact-safe-ssh"
  for kind in multiple-names duplicate; do
    cp "$TEST_ROOT/exact-safe-ssh" "$ssh_file"
    if [[ $kind == multiple-names ]]; then
      sed -i 's/^Host node-a-worker$/Host node-a-worker node-a-other/' "$ssh_file"
    else
      printf '\nHost node-a-worker\n  HostName 192.0.2.99\n' >> "$ssh_file"
    fi
    exact_before=$(snapshot "$EXACT_HOME" "$EXACT_CLAUDE")
    for form in preview apply; do
      arguments=(--dry-run)
      [[ $form == preview ]] || arguments=(--expect-digest "${digest//?/0}")
      set +e
      HOME=$FAKE_HOME "$SCRIPT" exact --nodes node-a --hosts node-a:198.51.100.99:2299 --reconcile "${arguments[@]}" > "$TEST_ROOT/exact-refuse.out" 2> "$TEST_ROOT/exact-refuse.err"
      status=$?
      set -e
      [[ $status -eq 2 && ! -s $TEST_ROOT/exact-refuse.out ]] || fail "$kind $form result"
      [[ $(snapshot "$EXACT_HOME" "$EXACT_CLAUDE") == "$exact_before" ]] || fail "$kind reconcile changed fixture"
      grep -Fq 'Host node-a-worker' "$TEST_ROOT/exact-refuse.err" || fail "$kind refusal omitted worker stanza"
      if [[ $kind == multiple-names ]]; then
        grep -Fq 'cannot reconcile node-a SSH stanza:' "$TEST_ROOT/exact-refuse.err" || fail "multi-name refusal"
      else
        grep -Fq 'ambiguous node-a SSH stanzas:' "$TEST_ROOT/exact-refuse.err" || fail "duplicate refusal"
      fi
    done
  done
  cp "$TEST_ROOT/exact-safe-ssh" "$ssh_file"
done
pass "multi-name and duplicated worker stanzas still refuse in both homes" "$start"

start=$(date +%s%N)
for unsafe_home in "$RECONCILE_HOME" "$RECONCILE_CLAUDE"; do
  chmod 755 "$unsafe_home"
  set +e
  reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/unsafe-home.out" 2> "$TEST_ROOT/unsafe-home.err"
  status=$?
  set -e
  chmod 700 "$unsafe_home"
  [[ $status -eq 2 ]] || fail "unsafe home accepted"
  grep -Fq "reconcile home identity, owner or mode mismatch: $unsafe_home" "$TEST_ROOT/unsafe-home.err" || fail "unsafe home unnamed"
done
for kind in symlink hardlink missing; do
  mv "$RECONCILE_HOME/ssh_config" "$TEST_ROOT/held-ssh"
  if [[ $kind == symlink ]]; then
    ln -s "$TEST_ROOT/held-ssh" "$RECONCILE_HOME/ssh_config"
  elif [[ $kind == hardlink ]]; then
    ln "$TEST_ROOT/held-ssh" "$RECONCILE_HOME/ssh_config"
  fi
  set +e
  reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/unsafe-ssh.out" 2> "$TEST_ROOT/unsafe-ssh.err"
  status=$?
  set -e
  rm -f "$RECONCILE_HOME/ssh_config"
  mv "$TEST_ROOT/held-ssh" "$RECONCILE_HOME/ssh_config"
  [[ $status -eq 2 && ! -s $TEST_ROOT/unsafe-ssh.out ]] || fail "unsafe SSH accepted"
  grep -Fq "reconcile requires unlinked regular SSH files: $RECONCILE_HOME/ssh_config" "$TEST_ROOT/unsafe-ssh.err" || fail "unsafe SSH refusal unnamed"
done
pass "reconcile refuses unsafe homes and linked SSH files" "$start"

start=$(date +%s%N)
if [[ ${SIGNIN_TEST_FAULTS:-0} == 1 ]]; then
set +e
SUPERLOOP_SIGNIN_TEST_FOREIGN_OWNER=1 reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/owner.out" 2> "$TEST_ROOT/owner.err"
status=$?
set -e
[[ $status -eq 2 && ! -s $TEST_ROOT/owner.out ]] || fail "foreign-owned home accepted"
grep -Fq 'reconcile home identity, owner or mode mismatch:' "$TEST_ROOT/owner.err" || fail "foreign-owned home refusal unnamed"
pass "reconcile refuses a home owned by another uid" "$start"
fi

start=$(date +%s%N)
if [[ ${SIGNIN_TEST_FAULTS:-0} == 1 ]]; then
before=$(snapshot)
set +e
SUPERLOOP_SIGNIN_TEST_SWAP_HOME=$RECONCILE_HOME reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/swap.out" 2> "$TEST_ROOT/swap.err"
status=$?
set -e
rmdir "$RECONCILE_HOME"
mv "$RECONCILE_HOME.held" "$RECONCILE_HOME"
[[ $status -eq 2 && ! -s $TEST_ROOT/swap.out ]] || fail "replaced locked home accepted"
grep -Fq "reconcile home identity, owner or mode mismatch: $RECONCILE_HOME" "$TEST_ROOT/swap.err" || fail "replaced locked home unnamed"
[[ $(snapshot) == "$before" ]] || fail "directory replacement changed retained home"
pass "reconcile detects replacement of a locked home" "$start"
fi

start=$(date +%s%N)
if [[ ${SIGNIN_TEST_FAULTS:-0} == 1 ]]; then
# Kill the fixture writer after its first publication; retain the removal ledger.
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/kill-plan.out"
digest=$(digest_from "$TEST_ROOT/kill-plan.out")
codex_before=$(cksum "$RECONCILE_HOME/ssh_config")
set +e
SUPERLOOP_SIGNIN_TEST_KILL_AFTER_RENAME=$TEST_ROOT/rename.log reconcile_home --nodes node-a --reconcile --expect-digest "$digest" > "$TEST_ROOT/kill-apply.out" 2> "$TEST_ROOT/kill-apply.err"
status=$?
set -e
[[ $status -ne 0 && ! -s $TEST_ROOT/kill-apply.out ]] || fail "killed apply printed success or plan"
[[ $(cat "$TEST_ROOT/rename.log") == "$RECONCILE_CLAUDE/ssh_config" ]] || fail "first publication was not Claude"
[[ $(cksum "$RECONCILE_HOME/ssh_config") == "$codex_before" ]] || fail "killed apply changed Codex header"
set +e
reconcile_home --nodes node-a --verify > "$TEST_ROOT/kill-verify.out"
status=$?
set -e
[[ $status -eq 1 ]] || fail "interrupted apply verified"
expect_line "$TEST_ROOT/kill-verify.out" "{\"loop\":\"alpha\",\"home\":\"$RECONCILE_HOME\",\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"ok\":false,\"missing\":[\"ssh-header\",\"known-hosts\"],\"varied\":[],\"varied_lines\":[]}" "interrupted header verification"
shopt -s nullglob
leftovers=("$RECONCILE_HOME"/.ssh_config.* "$RECONCILE_CLAUDE"/.ssh_config.*)
shopt -u nullglob
[[ ${#leftovers[@]} -eq 2 ]] || fail "killed apply staging residue"
before=$(snapshot)
set +e
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/residue.out" 2> "$TEST_ROOT/residue.err"
status=$?
set -e
[[ $status -eq 2 && ! -s $TEST_ROOT/residue.out && $(snapshot) == "$before" ]] || fail "residue preview did not refuse without writes"
grep -Fq -- "${leftovers[0]}" "$TEST_ROOT/residue.err" || fail "residue refusal omitted temporary file"
rm -- "${leftovers[@]}"
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/recover-plan.out"
digest=$(digest_from "$TEST_ROOT/recover-plan.out")
reconcile_home --nodes node-a --reconcile --expect-digest "$digest" > "$TEST_ROOT/recover-apply.out"
expect_line "$TEST_ROOT/recover-apply.out" "{\"charter\":\"$FAKE_HOME/.local/share/orchestration-instance/docs/tools/worker-charter.md\",\"digest\":\"$digest\",\"outcome\":\"applied\",\"replaced\":2}" "recovery completion result"
reconcile_home --nodes node-a --verify > "$TEST_ROOT/recover-verify.out"
[[ $(cksum "$RECONCILE_HOME/config.toml" "$RECONCILE_HOME/auth.json" "$RECONCILE_CLAUDE/.credentials.json" "$RECONCILE_CLAUDE/projects/transcript") == "$protected_before" ]] || fail "recovery changed protected files"
before=$(snapshot)
pass "killed apply preserves removal ledger names residue and recovers" "$start"
fi

start=$(date +%s%N)
before=$(snapshot)
for flags in '--reconcile' '--dry-run' '--reconcile --verify --dry-run' '--reconcile --dry-run --expect-digest bad' '--reconcile --expect-digest bad'; do
  read -r -a arguments <<< "$flags"
  set +e
  reconcile_home --nodes node-a "${arguments[@]}" > "$TEST_ROOT/reconcile-usage.out" 2> "$TEST_ROOT/reconcile-usage.err"
  status=$?
  set -e
  [[ $status -eq 2 && $(snapshot) == "$before" ]] || fail "invalid reconcile form wrote or succeeded"
done
printf 'Match all\n' >> "$RECONCILE_CLAUDE/ssh_config"
before=$(snapshot)
set +e
reconcile_home --nodes node-a --reconcile --dry-run > "$TEST_ROOT/reconcile-scope.out" 2> "$TEST_ROOT/reconcile-scope.err"
status=$?
set -e
[[ $status -eq 2 && $(snapshot) == "$before" ]] || fail "unknown scope wrote or succeeded"
expect_line "$TEST_ROOT/reconcile-scope.err" 'superloop-lane signin-home: reconcile does not support Match or Include scopes' "unknown scope reason"
pass "invalid forms and unsupported SSH scope refuse without writes" "$start"

echo "PASS sign-in-home cases (fault fixtures=${SIGNIN_TEST_FAULTS:-0})"

start=$(date +%s%N)
mkdir -p "$TEST_ROOT/runtime-bin"
cat > "$TEST_ROOT/runtime-bin/flatpak-spawn" <<'RUNTIME'
#!/bin/sh
printf '%s\n' "$@" > "$RUNTIME_ARGS"
printf 'runtime stdout\n'
printf 'runtime stderr\n' >&2
exit 27
RUNTIME
chmod +x "$TEST_ROOT/runtime-bin/flatpak-spawn"
runtime_env=(env -u CLAUDE_TOOLBOX -u GH_CONFIG_DIR
  "PATH=$TEST_ROOT/runtime-bin:/usr/bin:/bin" "HOME=$FAKE_HOME"
  "RUNTIME_ARGS=$TEST_ROOT/runtime.args" "CLAUDE_CONFIG_DIR=$TEST_ROOT/lane home")
for wrapper in runtime loop-gh; do
  rm -f "$TEST_ROOT/runtime.args"
  if [[ $wrapper == runtime ]]; then
    runtime_command=("${RUNTIME_TEST_BINARY:?Meson must bind the runtime binary}" run-toolbox)
  else
    runtime_command=("${SUPERLOOP_TEST_BINARY:?the suite must bind the built loop binary}" run-bridge gh --)
  fi
  if "${runtime_env[@]}" "${runtime_command[@]}" > "$TEST_ROOT/runtime.out" 2> "$TEST_ROOT/runtime.err"; then
    fail "$wrapper admitted missing configuration"
  fi
  [[ ! -e $TEST_ROOT/runtime.args ]] || fail "$wrapper transported missing configuration"
done
pass "runtime wrappers refuse missing deployment inputs before transport" "$start"

start=$(date +%s%N)
set +e
"${runtime_env[@]}" "CLAUDE_TOOLBOX=fixture box" "TMPDIR=$TEST_ROOT/temp root" \
  "${RUNTIME_TEST_BINARY:?Meson must bind the runtime binary}" run-toolbox one 'two words' > "$TEST_ROOT/runtime.out" 2> "$TEST_ROOT/runtime.err"
status=$?
set -e
[[ $status -eq 27 ]] || fail "Claude wrapper changed exit status"
printf '%s\n' --host toolbox run -c 'fixture box' env "CLAUDE_CONFIG_DIR=$TEST_ROOT/lane home" \
  "TMPDIR=$TEST_ROOT/temp root" claude one 'two words' > "$TEST_ROOT/runtime.expected"
cmp -s "$TEST_ROOT/runtime.expected" "$TEST_ROOT/runtime.args" || fail "Claude wrapper changed argv"
expect_line "$TEST_ROOT/runtime.out" 'runtime stdout' "Claude stdout"
expect_line "$TEST_ROOT/runtime.err" 'runtime stderr' "Claude stderr"
pass "Claude wrapper preserves explicitly selected inputs, streams and status" "$start"

start=$(date +%s%N)
set +e
"${runtime_env[@]}" "CLAUDE_TOOLBOX=fixture forge" "GH_CONFIG_DIR=$TEST_ROOT/forge home" \
  "${SUPERLOOP_TEST_BINARY:?the suite must bind the built loop binary}" run-bridge gh -- issue list > "$TEST_ROOT/runtime.out" 2> "$TEST_ROOT/runtime.err"
status=$?
set -e
[[ $status -eq 27 ]] || fail "forge wrapper changed exit status"
printf '%s\n' --host toolbox run -c 'fixture forge' env "GH_CONFIG_DIR=$TEST_ROOT/forge home" \
  gh issue list > "$TEST_ROOT/runtime.expected"
cmp -s "$TEST_ROOT/runtime.expected" "$TEST_ROOT/runtime.args" || fail "forge wrapper changed argv"
pass "forge wrapper preserves the explicit loop configuration" "$start"
