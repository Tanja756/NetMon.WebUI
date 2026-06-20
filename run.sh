#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d venv ]]; then
    echo "Виртуальное окружение не найдено. Запустите install.sh сначала."
    exit 1
fi

source venv/bin/activate

# Если нет аргументов — читаем конфиг или биндим на 0.0.0.0:8000
if [[ $# -eq 0 ]]; then
    exec python -m netmon.api_run --ip 0.0.0.0 --port 1234
fi

exec python -m netmon.api_run "$@"
