#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:?}/gate-sample.XXXXXX")
trap 'rm -rf "$fixture"' EXIT
source "$ROOT/infra/gate/run-slot.sh"
mkdir "$fixture/cgroup"
printf 'usage_usec 100\nuser_usec 60\nsystem_usec 40\nnr_throttled 2\n' > "$fixture/cgroup/cpu.stat"
printf '1048576\n' > "$fixture/cgroup/memory.current"
printf '2097152\n' > "$fixture/cgroup/memory.peak"
for resource in cpu memory io; do
  printf 'some avg10=1.10 avg60=2.20 avg300=3.30 total=100\nfull avg10=4.40 avg60=5.50 avg300=6.60 total=200\n' > "$fixture/cgroup/$resource.pressure"
done
samp_init "$fixture/cgroup"
{
  samp gate start
  sec fixture
  printf 'usage_usec 400\nuser_usec 260\nsystem_usec 140\nnr_throttled 5\n' > "$CG/cpu.stat"
  for resource in cpu memory io; do
    printf 'some avg10=2.10 avg60=3.20 avg300=4.30 total=150\nfull avg10=6.40 avg60=7.50 avg300=8.60 total=280\n' > "$CG/$resource.pressure"
  done
  samp_finish
  rm "$CG/memory.peak" "$CG/cpu.pressure"
  samp missing start
  samp missing end
} > "$fixture/log"
python3 - "$fixture/log" "$CG" <<'PY'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
for battery in ('gate', 'fixture'):
    start, end = [line for line in lines if line.startswith(f'SAMPLE {battery} ')]
    delta, = [line for line in lines if line.startswith(f'DELTA {battery} ')]
    assert f'cgroup={sys.argv[2]} scope=shared-or-unisolated' in start
    assert f'SAMPLE {battery} start ' in start
    assert f'SAMPLE {battery} end ' in end
    assert 'wall=' in delta
    assert 'own_user_s=' in delta and 'own_system_s=' in delta
    assert 'cpu_usage_usec=300.000000' in delta
    assert 'cpu_user_usec=200.000000' in delta
    assert 'cpu_system_usec=100.000000' in delta
    assert 'cpu_nr_throttled=3.000000' in delta
    assert 'memory_current=1048576' in start and 'memory_peak=2097152' in start
    for resource in ('cpu', 'memory', 'io'):
        for category, averages, total in [('some', (1.1, 2.2, 3.3), 50), ('full', (4.4, 5.5, 6.6), 80)]:
            for period, value in zip((10, 60, 300), averages):
                assert f'{resource}_{category}_avg{period}={value:.2f}' in start
            assert f'{resource}_{category}_total={total:.6f}' in delta
missing, = [line for line in lines if line.startswith('DELTA missing ')]
assert 'memory_peak=?' in missing and 'cpu_some_total=?' in missing
print('PASS gate sampler start/end, complete PSI, deltas, scope and missing counters')
PY
