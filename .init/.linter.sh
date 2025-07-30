#!/bin/bash
cd /home/kavia/workspace/code-generation/secure-access-management-service-140974-140983/auth_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

