#!/bin/sh
. venv/bin/activate
INOUTBOARD_SETTINGS=instance/settings.py exec python app.py
