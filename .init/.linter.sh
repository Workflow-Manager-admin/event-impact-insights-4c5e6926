#!/bin/bash
cd /home/kavia/workspace/code-generation/event-impact-insights-4c5e6926/backend_api
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

