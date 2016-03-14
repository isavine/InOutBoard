#!/bin/bash
cd "`dirname $0`"
. venv/bin/activate
INOUTBOARD_SETTINGS=instance/settings.py exec python app.py
