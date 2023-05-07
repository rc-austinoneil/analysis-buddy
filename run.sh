#!/bin/bash

echo "Updating SOC Buddy"
git pull
echo " "
echo "Updating team menu"
cd team && git pull && cd ..
echo " "
echo "Starting SOC Buddy"
source ./venv/bin/activate
./venv/bin/python3 socbuddy.py