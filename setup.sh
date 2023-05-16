#!/bin/bash

# Make sure you have python3-venv installed
echo "Installing dependencies"
echo "sudo apt install -y python3-venv"
sudo apt install -y python3-venv

# Setup enviroment
python3 -m venv venv
source ./venv/bin/activate

# Install requirements
./venv/bin/python3 -m pip install -r ./config/requirements.txt
if [ "$(uname)" == "Darwin" ]; then
./venv/bin/python3 -m pip install python-magic-bin
fi

# Setup gitignore for teams
git update-index --assume-unchanged team/teammenu.py
git update-index --assume-unchanged team/config/example_config.yaml

echo "team/teammenu.py" >> .git/info/exclude
echo "team/config/example_config.yaml" >> .git/info/exclude

#Print completion message
echo " "
echo "------------------------------------------"
echo "Setup complete!"
echo "You must configure ./config/config.yaml AND ./config/machinae.yaml before running Analysis Buddy!"
echo " "
echo "In machinae.yaml, you can enable tools by changing default: False to default: True"
echo "Note: Some of the machinae sources require you to enter an API key where it says 'CHANGEME'"
echo " "
echo "Once the two configuration files are setup, run the tool with: ./run.sh"
echo "------------------------------------------"