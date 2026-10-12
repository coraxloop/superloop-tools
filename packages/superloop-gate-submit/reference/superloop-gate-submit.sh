#!/usr/bin/env bash
# superloop-gate-submit — server-side compile/lint/test verdict for one Codex
# lane's UNCOMMITTED worktree, without giving the lane any access.
#
# Flow (one-way trust, host -> server, results as data):
#   1. snapshot the worktree with a temporary index (the lane's tree is
#      never touched: no add, no commit, no stash);
#   2. push the snapshot commit to the hub as refs/lanes/verify-<name>;
#   3. run fmt --check, workspace clippy, and the named packages'
#      tests on the shared instance at idle priority;
#   4. print the server log tail and a RUN-REPORT line; exit with the
#      server verdict.
#
# Usage:
#   superloop-gate-submit -p <pkg[,pkg...]> [-n <name>] [-A] <worktree>
#
#   -p  cargo package names to test (comma-separated; mandatory)
#   -n  lane name for the ref and report (default: basename of worktree)
#   -A  run the named packages' tests with --all-features (the project-a
#       verification rule: feature-gated tests are part of the surface)
#   -D  also run RUSTDOCFLAGS='-D warnings' cargo doc --no-deps for the
#       named packages (the section-21.2 documentation bar)
#
# The orchestrator calls this between `codex exec resume` steps and
# feeds the output back to the lane. Typical wall: 1-6 min depending on
# the packages named (wall-time ruling: the RUN-REPORT line carries it).
set -euo pipefail

HUB_REMOTE="${LANE_VERIFY_REMOTE:-shared}"

for profile_variable in \
  LANE_VERIFY_SSH \
  LANE_VERIFY_CLONE \
  LANE_VERIFY_REMOTE_RUNNER \
  LANE_VERIFY_RUST_ENV
do
  [ -n "${!profile_variable:-}" ] || {
    echo "superloop-gate-submit: usage_error: $profile_variable is required" >&2
    exit 2
  }
done

SSH_ALIAS="$LANE_VERIFY_SSH"
SERVER_CLONE="$LANE_VERIFY_CLONE"
REMOTE_RUNNER="$LANE_VERIFY_REMOTE_RUNNER"
RUST_ENV="$LANE_VERIFY_RUST_ENV"

packages="" name="" doc_check="" all_features=""
while getopts "p:n:AD" opt; do
  case "$opt" in
    p) packages="$OPTARG" ;;
    n) name="$OPTARG" ;;
    A) all_features="--all-features" ;;
    D) doc_check=1 ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))

[ -n "$packages" ] || { echo "superloop-gate-submit: -p <packages> is mandatory" >&2; exit 2; }
[ $# -eq 1 ] || { echo "superloop-gate-submit: exactly one worktree argument required" >&2; exit 2; }
worktree="$(cd "$1" && pwd)"
[ -n "$name" ] || name="$(basename "$worktree")"
ref="refs/lanes/verify-$name"

start=$(date +%s)

# 1. Snapshot without touching the lane's index or history.
tmp_index="$(mktemp)"
trap 'rm -f "$tmp_index"' EXIT
head="$(git -C "$worktree" rev-parse HEAD)"
cp "$(git -C "$worktree" rev-parse --absolute-git-dir)/index" "$tmp_index"
snapshot=$(
  cd "$worktree" &&
  GIT_INDEX_FILE="$tmp_index" git add -A . >&2 &&
  tree="$(GIT_INDEX_FILE="$tmp_index" git write-tree)" &&
  git commit-tree "$tree" -p "$head" -m "superloop-gate-submit snapshot: $name"
)

# 2. Push the snapshot to the hub under a lane ref.
git -C "$worktree" push -q -f "$HUB_REMOTE" "$snapshot:$ref"

# 3. Verify on the server. The remote script is fixed text (no lane
#    content is interpolated into it); the snapshot travels only as a
#    git object. Results come back as data. The whole run goes through
#    the configured remote runner, whose stderr
#    RUN-REPORT line carries the mandated space fields; the script
#    travels on stdin (`bash -s`), expanded client-side as before.
test_args=""
IFS=',' read -ra pkgs <<< "$packages"
for p in "${pkgs[@]}"; do test_args="$test_args -p $p"; done

set +e
ssh "$SSH_ALIAS" "$REMOTE_RUNNER" <<REMOTE 2>&1 | tail -60
set -e; . $RUST_ENV; cd $SERVER_CLONE
git fetch -q origin '+$ref:$ref'
git checkout -qf --detach $ref && git clean -qfdx
echo '== fmt =='; time nice -n19 cargo fmt --all -- --check
echo '== clippy =='; time nice -n19 cargo clippy --workspace --all-targets --locked -- -D warnings
echo '== test =='; time nice -n19 cargo test $test_args $all_features --locked
$( [ -n "$doc_check" ] && echo "echo '== doc =='; time nice -n19 env RUSTDOCFLAGS='-D warnings' cargo doc --no-deps $test_args --locked" )
REMOTE
verdict=$?
set -e

wall=$(( $(date +%s) - start ))
v=ok; [ "$verdict" -ne 0 ] && v=FAILED
echo "RUN-REPORT lane=verify-$name exit=$verdict wall=${wall}s verdict=$v ref=$ref"
exit "$verdict"
