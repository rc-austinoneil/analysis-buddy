#!/bin/bash

echo "Updating Analysis Buddy"
git pull
echo " "
echo "Updating team menu"
cd team && git pull && cd ..
echo " "
echo "Starting Analysis Buddy"
source ./venv/bin/activate
./venv/bin/python3 analysisbuddy.py