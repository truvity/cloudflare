#!/usr/bin/env bash
# Golden renders: every tests/cases/<chart>/<case>/values.yaml is rendered
# with `helm template` and compared byte-for-byte against
# tests/golden/<chart>/<case>.yaml. A template change that alters output
# therefore shows up as a reviewable diff, with no cluster involved.
#
# A LIBRARY chart renders nothing by itself — `helm template` refuses one —
# so its cases are rendered through tests/harness/<chart>, a consumer chart
# that stands in for the application including it and reads the case's
# values.
#
#   hack/golden.sh          compare (CI)
#   hack/golden.sh update   regenerate the golden files
set -euo pipefail

mode="${1:-check}"
root="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

for values in "$root"/tests/cases/*/*/values.yaml; do
  case_dir="$(dirname "$values")"
  case_name="$(basename "$case_dir")"
  chart="$(basename "$(dirname "$case_dir")")"
  golden="$root/tests/golden/$chart/$case_name.yaml"

  chart_dir="$root/charts/$chart"
  if [ -d "$root/tests/harness/$chart" ]; then
    chart_dir="$root/tests/harness/$chart"
  fi

  # A case may list preset files (one path per line, relative to the chart
  # directory) in a `presets` file: they are passed before the case's values,
  # as a consumer lists them in `valueFiles`.
  preset_args=()
  if [ -f "$case_dir/presets" ]; then
    while IFS= read -r preset; do
      [ -n "$preset" ] && preset_args+=(-f "$root/charts/$chart/$preset")
    done < "$case_dir/presets"
  fi

  rendered="$(helm template "$chart" "$chart_dir" \
      --namespace "$(cat "$case_dir/namespace" 2>/dev/null || echo default)" \
      ${preset_args[@]+"${preset_args[@]}"} \
      -f "$values")"

  if [ "$mode" = update ]; then
    mkdir -p "$(dirname "$golden")"
    printf '%s\n' "$rendered" > "$golden"
    echo "updated $golden"
    continue
  fi

  if ! diff -u "$golden" <(printf '%s\n' "$rendered"); then
    echo "GOLDEN MISMATCH: $chart/$case_name — run 'just golden' and review the diff"
    fail=1
  fi
done

[ "$fail" = 0 ] && echo "golden renders match"
exit $fail
