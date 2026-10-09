#!/usr/bin/env bash
# Lance les tests du plugin sans toucher au venv d'Hermes.
#   1. tests unitaires et scénarios (bibliothèque standard + pytest) ;
#   2. tests d'intégration contre le vrai code d'Hermes (HERMES_HOME jetable).
# Usage : scripts/run_tests.sh [dossier hermes-agent]   (défaut : ~/.hermes/hermes-agent)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMES_DIR="${1:-$HOME/.hermes/hermes-agent}"

HPY=""
for candidate in "$HERMES_DIR/venv/bin/python" "$HERMES_DIR/.venv/bin/python"; do
  if [ -x "$candidate" ]; then HPY="$candidate"; break; fi
done
if [ -z "$HPY" ] && command -v hermes >/dev/null 2>&1; then
  shebang="$(head -1 "$(command -v hermes)" | sed -n 's/^#! *//p' | awk '{print $1}')"
  if [ -n "$shebang" ] && [ -x "$shebang" ]; then HPY="$shebang"; fi
fi
if [ -z "$HPY" ]; then
  echo "Python d'Hermes introuvable (passe le dossier hermes-agent en argument)." >&2
  exit 2
fi
echo "Python d'Hermes : $HPY ($("$HPY" --version 2>&1))"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if command -v uv >/dev/null 2>&1; then
  uv venv -q --python "$HPY" "$WORK/venv"
  uv pip install -q --python "$WORK/venv/bin/python" pytest
else
  "$HPY" -m venv "$WORK/venv"
  "$WORK/venv/bin/python" -m pip install -q pytest
fi
PY="$WORK/venv/bin/python"

echo "== Tests unitaires et scénarios"
"$PY" -m pytest -q -p no:cacheprovider "$REPO/tests" --ignore="$REPO/tests/integration"

echo "== Tests d'intégration avec Hermes ($HERMES_DIR, commit $(git -C "$HERMES_DIR" rev-parse --short HEAD 2>/dev/null || echo '?'))"
SITE="$("$HPY" -c 'import site; print(":".join(site.getsitepackages()))')"
cd "$HERMES_DIR"
PYTHONPATH="$HERMES_DIR:$SITE" "$PY" -m pytest -q -p no:cacheprovider -rs -s "$REPO/tests/integration"
