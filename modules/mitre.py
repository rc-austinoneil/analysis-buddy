import analysisbuddy
from mitreattack.stix20 import MitreAttackData
from config import fontcolors

bcolors = fontcolors.bcolors()


# Tools
def check_mitre_id(mitre_id):
    mitre_id = str(mitre_id)
    if mitre_id[0] == "T":
        return mitre_id
    elif mitre_id[0] == "t":
        return "T" + mitre_id[1:]
    elif mitre_id[0].isalpha() and mitre_id[0] != "T":
        analysisbuddy.error_message(
            f"Invalid MITRE ID ({mitre_id}). Must start with 'T' or 't'."
        )
        return None
    else:
        return "T" + mitre_id


def get_mitre_details(mitre_id):
    """
    This function will return Mitre details for a given Mitre ID
    """
    try:

        def get_mitre_url(mitre_id):
            """
            This function will return a valid URL for a Mitre ID
            """
            if "." in mitre_id:
                mitre_url_sanitized = mitre_id.replace(".", "/")
                mitre_url = "https://attack.mitre.org/techniques/" + mitre_url_sanitized
            else:
                mitre_url = "https://attack.mitre.org/techniques/" + mitre_id
            return mitre_url

        mitre_attack_data = MitreAttackData(
            "./config/json_lookups/mitre-enterprise-attack.json"
        )
        mitre_object = mitre_attack_data.get_object_by_attack_id(
            mitre_id, "attack-pattern"
        )
        mitre_details = {
            "id": mitre_id,
            "name": mitre_object.get("name"),
            "phase_name": mitre_object.get("kill_chain_phases")[0].get("phase_name"),
            "url": get_mitre_url(mitre_id),
            "created": str(mitre_object.get("created")),
            "modified": str(mitre_object.get("modified")),
            "platforms": mitre_object.get("x_mitre_platforms"),
            "description": mitre_object.get("description"),
        }
        return mitre_details

    except AttributeError:
        analysisbuddy.error_message(
            f"Mitre ID ({mitre_id}) not found. Check the Mitre ID and try again."
        )
        return None

    except Exception:
        analysisbuddy.error_message(f"Failed to get Mitre details for {mitre_id}.")
        return None


def mitre_lookup():
    """
    This function will lookup a Mitre ID in the Mitre Enterprise Attack Framework JSON file
    """
    try:
        analysisbuddy.title_bar("Mitre Lookup")
        mitre_id = analysisbuddy.ask_for_user_input("Enter the MITRE ID to lookup")
        mitre_id = check_mitre_id(mitre_id)
        if mitre_id:
            analysisbuddy.info_message(f"Looking up Mitre ID: {mitre_id}")
            analysisbuddy.download_file_from_internet(
                url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                file_path="./config/json_lookups/mitre-enterprise-attack.json",
            )
            technique = get_mitre_details(mitre_id)
            if technique:
                analysisbuddy.next_result_message(f"Technique: {mitre_id}")
                analysisbuddy.print_json(technique, False)
                if "." in mitre_id:
                    parent_technique = get_mitre_details(mitre_id.split(".")[0])
                    analysisbuddy.next_result_message(
                        f'Parent Technique: {mitre_id.split(".")[0]}'
                    )
                    analysisbuddy.print_json(parent_technique, False)
    except Exception as e:
        analysisbuddy.error_message("Failed to run MITRE lookup", str(e))
    mitre_lookup() if analysisbuddy.ask_to_run_again() else analysisbuddy.main_menu()
