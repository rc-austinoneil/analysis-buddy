#!/bin/bash
echo " "
echo "===== Analysis Buddy Setup ====="

# Check if venv exists, if so, remove it
if [ -d "./venv/" ]; then
    echo "Removing existing enviroment"
    rm -r ./venv
fi

echo "Installing dependencies"

# Setup enviroment
python3 -m venv venv
source ./venv/bin/activate
./venv/bin/python3 -m pip install -r ./config/requirements.txt

# If your internal team has a requirements.txt file, install those too
if [ -e "./team/config/requirements.txt" ]; then
    echo "Installing team dependencies"
    ./venv/bin/python3 -m pip install -r ./team/config/requirements.txt
fi

# If mac, install python-magic-bin
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
if [ -f "./config/config.yaml" ] && [ -f "./config/machinae.yaml" ]; then
    echo "You have existing config files, check them to make sure they are up to date!"
    echo "New additions to the tool will be added to the example config files."
    if [ -f "./team/config/config.yaml" ]; then
        echo " "
        echo "You have an existing team config file, check it to make sure its up to date!" 
        echo "New additions to the tool will be added to the example config files."
    fi
    echo " "
    echo "You can now run Analysis Buddy with: ./run.sh"
    echo "------------------------------------------"
else
    echo "You must configure ./config/config.yaml AND ./config/machinae.yaml before running Analysis Buddy!"
    echo " "
    echo "In the machinae config, you can enable tools by changing 'default: False' to 'default: True'"
    echo "Note: Some of the machinae sources require you to enter an API key where it says 'CHANGEME'"
    echo " "
    echo "Once the two configuration files are setup, run the tool with: ./run.sh"
fi
    echo "------------------------------------------"

