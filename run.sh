#!/usr/bin/env bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.app
export FLASK_RUN_HOST=0.0.0.0
export FLASK_RUN_PORT=5000
export SECRET_KEY=${SECRET_KEY:-"dev-secret-change-me"}
flask run
