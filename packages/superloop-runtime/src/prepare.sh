# Embedded container payload. Positional arguments keep account and path bytes
# out of shell source; a completed preparation publishes its identity last.
set -eu
uid=$1
account=$2
home=$3
identity=$4
if ! getent passwd "$account" >/dev/null; then
  useradd -u "$uid" -o -M -d "$home" -s /bin/bash "$account"
fi
test "$(id -u "$account")" = "$uid"
dnf install -y -q git openssh-clients jq python3 bubblewrap ripgrep procps-ng which >/dev/null 2>&1
python3 - "$home" <<'PY'
import pathlib,shlex,sys
pathlib.Path('/etc/profile.d/superloop-runtime-tmpdir.sh').write_text(
    'export TMPDIR=' + shlex.quote(sys.argv[1] + '/.cache/tmp') + '\n')
PY
chmod 644 /etc/profile.d/superloop-runtime-tmpdir.sh
git --version
ssh -V
bwrap --version
test ! -e /run/host
test "$(awk '$5 == "/tmp" { n++ } END { print n+0 }' /proc/self/mountinfo)" = 1
mkdir -p /var/lib/superloop-runtime
printf '%s\n' "$identity" > /var/lib/superloop-runtime/ready.next
mv /var/lib/superloop-runtime/ready.next /var/lib/superloop-runtime/ready
