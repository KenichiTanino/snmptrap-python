#!/bin/bash

CURRENT=$(cd $(dirname $0);pwd)

source ${CURRENT}/venv/bin/activate

python3 ${CURRENT}/snmprecv.py
