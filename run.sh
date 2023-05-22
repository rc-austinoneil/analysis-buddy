#!/bin/bash

read -p "Do you want to update the tool? (y/n): " answer

if [[ "$answer" == [Yy]* ]]; then
    check_requirements() {
        local requirements_file="$1"
        local missing_packages=()

        while IFS= read -r package || [[ -n "$package" ]]; do
            if [[ "$package" == git+* ]]; then
                continue  # Skip Git package entries
            fi

            package_name="${package%%=*}"  # Remove version if present
            package_name="${package_name%%<=*}"  # Remove version constraint operator if present

            if ! ./venv/bin/pip freeze | grep -q "^$package_name=="; then
                missing_packages+=("$package")
            fi
        done < "$requirements_file"

        if [ ${#missing_packages[@]} -eq 0 ]; then
            echo "All packages are installed."
        else
            echo "Installing missing packages in $requirements_file:"
            for package in "${missing_packages[@]}"; do
                ./venv/bin/python3 -m pip install "$package"
            done
        fi
    }

    echo "Updating Analysis Buddy"
    git pull
    source ./venv/bin/activate
    check_requirements "./config/requirements.txt"


    if [ -f "./custom/config/requirements.txt" ]; then
        echo " "
        echo "Updating custom menu"
        cd custom && git pull && cd ..
        check_requirements "./custom/config/requirements.txt"
    fi
fi

# Start the tool
echo "Starting Analysis Buddy"
source ./venv/bin/activate
./venv/bin/python3 analysisbuddy.py