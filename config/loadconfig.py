import strictyaml, sys
from config import fontcolors

bcolors = fontcolors.bcolors()


def load_buddy_config():
    """
    This function will load the ./config/config.yaml file and return the configvars object
    """
    try:
        f = open("./config/config.yaml", "r")
        configvars = strictyaml.load(f.read())
        f.close()
        return configvars
    except FileNotFoundError:
        print(
            f"{bcolors.ERROR}Error: ./config/config.yaml not found.\nPlease configure the config file before launching Soc Buddy. See readme for documentation.{bcolors.ENDC}"
        )
        sys.exit()


def check_buddy_config(key):
    """
    This function will check if an API key is set in the config.yaml file
    """
    configvars = load_buddy_config()
    if configvars[key] != "Enter API Key Here":
        return True
    else:
        raise Exception(f"{key} not set in ./config/config.yaml")


def check_team_config(key):
    """
    This function will check if an API key is set in the config.yaml file
    """
    configvars = load_team_config()
    if configvars[key] != "Enter API Key Here":
        return True
    else:
        raise Exception(f"{key} not set in ./team/config/config.yaml")


def load_team_config():
    """
    This function will load the ./team/config/config.yaml file and return the configvars object
    """
    try:
        f = open("./team/config/config.yaml", "r")
        configvars = strictyaml.load(f.read())
        f.close()
        return configvars
    except FileNotFoundError:
        print(
            f"{bcolors.ERROR}Error: ./team/config/config.yaml not found.\nPlease configure your team config file before launching Soc Buddy. See readme for documentation.{bcolors.ENDC}"
        )
        sys.exit()


def load_machinae_config():
    try:
        with open("./config/machinae.yaml", "r") as file:
            return "./config/machinae.yaml"
    except FileNotFoundError:
        print(
            f"{bcolors.ERROR}Error: ./config/machinae.yaml not found.\nPlease setup the machinae config file before launching Soc Buddy. See readme for documentation.{bcolors.ENDC}"
        )
        sys.exit()
