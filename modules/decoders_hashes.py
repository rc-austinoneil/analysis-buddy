import analysisbuddy
import base64
import html.parser
import re
import urllib.parse
import requests
import json
import os
from config import fontcolors, loadconfig
from unfurl import core

configvars = loadconfig.load_buddy_config()

bcolors = fontcolors.bcolors()
linksFoundList = []


# Menu
def menu():
    analysisbuddy.title_bar("Decoders & Hash Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "ProofPoint Decoder", "tool")
    analysisbuddy.menu_item(2, "URL Decoder", "tool")
    analysisbuddy.menu_item(3, "Office SafeLinks Decoder", "tool")
    analysisbuddy.menu_item(4, "URL unShortener", "tool")
    analysisbuddy.menu_item(5, "Base64 Decoder", "tool")
    analysisbuddy.menu_item(6, "Unfurl URL", "tool")
    analysisbuddy.menu_item(7, "JSON Pretty Print", "tool")
    analysisbuddy.menu_item(8, "Hybrid Analysis Lookup", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        proofpoint_decoder()
    if choice == "2":
        url_decoder()
    if choice == "3":
        safelinks_decoder()
    if choice == "4":
        unshorten_url()
    if choice == "5":
        b64_decoder()
    if choice == "6":
        unfurl_url()
    if choice == "7":
        json_pprint()
    if choice == "8":
        hybrid_analysis()
    if choice == "0":
        analysisbuddy.main_menu()


# Tools
def decodev1(rewrittenurl):
    match = re.search(r"u=(.+?)&k=", rewrittenurl)
    if match:
        urlencodedurl = match.group(1)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)


def decodev2(rewrittenurl):
    match = re.search(r"u=(.+?)&[dc]=", rewrittenurl)
    if match:
        specialencodedurl = match.group(1)
        trans = str.maketrans("-_", "%/")
        urlencodedurl = specialencodedurl.translate(trans)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        url = html.unescape(htmlencodedurl)
        url = re.sub("http://", "", url)
        if url not in linksFoundList:
            linksFoundList.append(url)


def decodev3(rewrittenurl):
    match = re.search(r"v3/__(?P<url>.+?)__;", rewrittenurl)
    if match:
        url = match.group("url")
        if re.search(r"\*(\*.)?", url):
            url = re.sub("\*", "+", url)
            if url not in linksFoundList:
                linksFoundList.append(url)


def proofpoint_decoder():
    try:
        analysisbuddy.title_bar("ProofPoint Decoder")
        rewrittenurl = analysisbuddy.ask_for_user_input("Enter URL")
        match = re.search(r"https://urldefense.proofpoint.com/(v[0-9])/", rewrittenurl)
        matchv3 = re.search(r"urldefense.com/(v3)/", rewrittenurl)
        if match:
            if match.group(1) == "v1":
                decodev1(rewrittenurl)
                for each in linksFoundList:
                    analysisbuddy.print_json({"Decoded Link": each})
                    linksFoundList.clear()
            elif match.group(1) == "v2":
                decodev2(rewrittenurl)
                for each in linksFoundList:
                    analysisbuddy.print_json({"Decoded Link": each})
                    linksFoundList.clear()

        if matchv3 is not None:
            if matchv3.group(1) == "v3":
                decodev3(rewrittenurl)
                for each in linksFoundList:
                    analysisbuddy.print_json({"Decoded Link": each})
                    linksFoundList.clear()
            else:
                analysisbuddy.error_message(
                    f"No valid URL found in input: {rewrittenurl}"
                )
    except Exception as e:
        analysisbuddy.error_message("Failed to decode ProofPoint URL", str(e))
    proofpoint_decoder() if analysisbuddy.ask_to_run_again() else menu()


def url_decoder():
    """
    This function will decode a URL using urllib.parse.unquote
    """
    try:
        analysisbuddy.title_bar("URL Decoder")
        url = analysisbuddy.ask_for_user_input("Enter URL")
        decodedUrl = urllib.parse.unquote(url)
        output = {"url:": decodedUrl}
        analysisbuddy.print_json(output)
        analysisbuddy.clipboard_copy(decodedUrl)
    except Exception as e:
        analysisbuddy.error_message("Failed to decode URL", str(e))
    url_decoder() if analysisbuddy.ask_to_run_again() else menu()


def safelinks_decoder():
    """
    This function will replace the SafeLinks URL with the original URL
    """
    try:
        analysisbuddy.title_bar("SafeLinks Decoder")
        url = analysisbuddy.ask_for_user_input("Enter URL")
        dcUrl = urllib.parse.unquote(url)
        dcUrl = dcUrl.replace(
            "https://nam02.safelinks.protection.outlook.com/?url=", ""
        )
        output = {"url": dcUrl}
        analysisbuddy.print_json(output)
        analysisbuddy.clipboard_copy(dcUrl)
    except Exception as e:
        analysisbuddy.error_message("Failed to decode SafeLink", str(e))
    safelinks_decoder() if analysisbuddy.ask_to_run_again() else menu()


def unshorten_url():
    """
    This function will unshorten a URL using unshorten.me
    """
    try:
        analysisbuddy.title_bar("URL UnShortener")
        link = analysisbuddy.ask_for_user_input("Enter URL")
        req = requests.get(str("https://unshorten.me/s/" + link))
        output = {"url": req.text}
        analysisbuddy.print_json(output)
        analysisbuddy.clipboard_copy(req.text)
    except Exception as e:
        analysisbuddy.error_message("Failed to unshorten URL", str(e))
    unshorten_url() if analysisbuddy.ask_to_run_again() else menu()


def b64_decoder():
    """
    This function will decode a base64 encoded string using base64.b64decode
    """
    try:
        analysisbuddy.title_bar("B64 Decoder")
        b64_string = analysisbuddy.ask_for_user_input("Enter B64")
        decoded_bytes = base64.b64decode(b64_string)
        decoded_str = decoded_bytes.decode("utf-8")
        output = {"input b64": b64_string, "decoded b64": decoded_str}
        analysisbuddy.print_json(output)
    except Exception as e:
        analysisbuddy.error_message("No Base64 Encoded String Found", str(e))
    b64_decoder() if analysisbuddy.ask_to_run_again() else menu()


def unfurl_url():
    """
    This function will unfurl a URL using the unfurl library
    """
    try:
        analysisbuddy.title_bar("Unfurl URL")
        url_to_unfurl = analysisbuddy.ask_for_user_input("Enter URL")
        unfurl_instance = core.Unfurl()
        unfurl_instance.add_to_queue(data_type="url", key=None, value=url_to_unfurl)
        unfurl_instance.parse_queue()
        print(unfurl_instance.generate_text_tree())
    except Exception as e:
        analysisbuddy.error_message("No valid URL found", str(e))
    unfurl_url() if analysisbuddy.ask_to_run_again() else menu()


def json_pprint(clear_screen=True):
    """
    This function will pretty print a JSON blob you paste into the terminal
    """
    analysisbuddy.title_bar("PPrint JSON input", False)
    input_from_file = str(
        input(f"{bcolors.INPUT}Enter a filepath? (Y/N) {bcolors.ENDC}")
    )
    if input_from_file.upper() == "Y":
        input_file_path = analysisbuddy.ask_for_user_input(
            "Enter the filepath to your json file"
        )
        with open(input_file_path, "r") as input_file:
            json_data = json.load(input_file)
            for each in json_data:
                analysisbuddy.print_json(each)
    else:
        print(
            f"{bcolors.INPUT}Enter your JSON Blob below.\nEnter + CTRL+D to finish input.\n{bcolors.ENDC}"
        )
        try:
            line = ""
            while True:
                try:
                    line += input()
                except EOFError:
                    break
            if clear_screen:
                os.system("clear")
            analysisbuddy.print_json(json.loads(line))
        except Exception as e:
            analysisbuddy.error_message("Error parsing JSON input.", str(e))
        except KeyboardInterrupt:
            analysisbuddy.error_message("Keyboard Interrupt")
    json_pprint(
        False
    ) if analysisbuddy.ask_to_run_again() else analysisbuddy.main_menu()


def hybrid_analysis():
    """
    This function will lookup a hash in Hybrid Analysis.
    """
    try:
        if loadconfig.check_buddy_config("HYBRID_ANALYSIS_API_KEY"):
            analysisbuddy.title_bar("Hybrid Analysis Lookup")
            hash_input = analysisbuddy.ask_for_user_input("Enter the hash to lookup")
            response = requests.post(
                "https://www.hybrid-analysis.com/api/v2/search/hash",
                headers={
                    "api-key": str(configvars["HYBRID_ANALYSIS_API_KEY"]),
                    "user-agent": "Falcon Sandbox",
                    "accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={"hash": hash_input},
            )

            if response.status_code == 200:
                analysisbuddy.print_json(response.json())
                analysisbuddy.info_message(
                    f"https://www.hybrid-analysis.com/sample/{hash_input}", True
                )
            else:
                raise Exception("Hash not found in Hybrid Analysis.")
    except Exception as e:
        analysisbuddy.error_message("Failed to run Hybrid Analysis", str(e))
    hybrid_analysis() if analysisbuddy.ask_to_run_again() else analysisbuddy.main_menu()
