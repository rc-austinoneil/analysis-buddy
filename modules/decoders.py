import socbuddy
import base64
import html.parser
import re
import urllib.parse
import requests
import json
import os
from config import fontcolors
from unfurl import core
from bs4 import BeautifulSoup

bcolors = fontcolors.bcolors()
linksFoundList = []


# Menu
def menu():
    socbuddy.title_bar("Decoders")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "ProofPoint Decoder", "tool")
    socbuddy.menu_item(2, "URL Decoder", "tool")
    socbuddy.menu_item(3, "Office SafeLinks Decoder", "tool")
    socbuddy.menu_item(4, "URL unShortener", "tool")
    socbuddy.menu_item(5, "Base64 Decoder", "tool")
    socbuddy.menu_item(6, "Unfurl URL", "tool")
    socbuddy.menu_item(7, "JSON Pretty Print", "tool")
    socbuddy.menu_item(8, "Chrome Extension Lookup", "tool")
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
        chrome_extension_lookup()
    if choice == "0":
        socbuddy.main_menu()


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
        socbuddy.title_bar("ProofPoint Decoder")
        rewrittenurl = socbuddy.ask_for_user_input("Enter URL")
        match = re.search(r"https://urldefense.proofpoint.com/(v[0-9])/", rewrittenurl)
        matchv3 = re.search(r"urldefense.com/(v3)/", rewrittenurl)
        if match:
            if match.group(1) == "v1":
                decodev1(rewrittenurl)
                for each in linksFoundList:
                    socbuddy.print_json({"Decoded Link": each})
                    linksFoundList.clear()
            elif match.group(1) == "v2":
                decodev2(rewrittenurl)
                for each in linksFoundList:
                    socbuddy.print_json({"Decoded Link": each})
                    linksFoundList.clear()

        if matchv3 is not None:
            if matchv3.group(1) == "v3":
                decodev3(rewrittenurl)
                for each in linksFoundList:
                    socbuddy.print_json({"Decoded Link": each})
                    linksFoundList.clear()
            else:
                socbuddy.error_message(f"No valid URL found in input: {rewrittenurl}")
    except Exception:
        socbuddy.error_message("Failed to decode ProofPoint URL")
    proofpoint_decoder() if socbuddy.ask_to_run_again() else menu()


def url_decoder():
    try:
        socbuddy.title_bar("URL Decoder")
        url = socbuddy.ask_for_user_input("Enter URL")
        decodedUrl = urllib.parse.unquote(url)
        output = {"url:": decodedUrl}
        socbuddy.print_json(output)
        socbuddy.clipboard_copy(decodedUrl)
    except Exception:
        socbuddy.error_message("Failed to decode URL")
    url_decoder() if socbuddy.ask_to_run_again() else menu()


def safelinks_decoder():
    try:
        socbuddy.title_bar("SafeLinks Decoder")
        url = socbuddy.ask_for_user_input("Enter URL")
        dcUrl = urllib.parse.unquote(url)
        dcUrl = dcUrl.replace(
            "https://nam02.safelinks.protection.outlook.com/?url=", ""
        )
        output = {"url": dcUrl}
        socbuddy.print_json(output)
        socbuddy.clipboard_copy(dcUrl)
    except Exception:
        socbuddy.error_message("Failed to decode SafeLink")
    safelinks_decoder() if socbuddy.ask_to_run_again() else menu()


def unshorten_url():
    try:
        socbuddy.title_bar("URL UnShortener")
        link = socbuddy.ask_for_user_input("Enter URL")
        req = requests.get(str("https://unshorten.me/s/" + link))
        output = {"url": req.text}
        socbuddy.print_json(output)
        socbuddy.clipboard_copy(req.text)
    except Exception:
        socbuddy.error_message("Failed to unshorten URL")
    unshorten_url() if socbuddy.ask_to_run_again() else menu()


def b64_decoder():
    try:
        socbuddy.title_bar("B64 Decoder")
        b64_string = socbuddy.ask_for_user_input("Enter B64")
        decoded_bytes = base64.b64decode(b64_string)
        decoded_str = decoded_bytes.decode("utf-8")
        output = {"decoded b64": decoded_str}
        socbuddy.print_json(output)
    except Exception:
        socbuddy.error_message("No Base64 Encoded String Found")
    b64_decoder() if socbuddy.ask_to_run_again() else menu()


def unfurl_url():
    try:
        socbuddy.title_bar("Unfurl URL")
        url_to_unfurl = socbuddy.ask_for_user_input("Enter URL")
        unfurl_instance = core.Unfurl()
        unfurl_instance.add_to_queue(data_type="url", key=None, value=url_to_unfurl)
        unfurl_instance.parse_queue()
        print(unfurl_instance.generate_text_tree())
    except Exception:
        socbuddy.error_message("No valid URL found")
    unfurl_url() if socbuddy.ask_to_run_again() else menu()


def json_pprint(clear_screen=True):
    socbuddy.title_bar("PPrint JSON input", False)
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
        socbuddy.print_json(json.loads(line))
    except Exception:
        socbuddy.error_message("Error parsing JSON input.")
    except KeyboardInterrupt:
        socbuddy.error_message("Keyboard Interrupt")
    json_pprint(False) if socbuddy.ask_to_run_again() else socbuddy.main_menu()


def chrome_extension_lookup():
    try:
        socbuddy.title_bar("Chrome Extension Details")
        extension_id = socbuddy.ask_for_user_input("Enter the Chrome Extension ID")
        url = f"https://chrome.google.com/webstore/detail/{extension_id}"
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")

        output = {
            "Extension name": soup.find("h1", {"class": "e-f-w"}).text.strip(),
            "Version": soup.find("span", {"class": "C-b-p-D-Xe h-C-b-p-D-md"}).text,
            "Size": soup.find("span", {"class": "C-b-p-D-Xe h-C-b-p-D-za"}).text,
            "Updated": soup.find("span", {"class": "C-b-p-D-Xe h-C-b-p-D-xh-hh"}).text,
            "Number of users": soup.find("span", {"class": "e-f-ih"}).text,
            "Developer": soup.find("a", {"class": "e-f-y"}).text,
            "url": url,
        }
        socbuddy.print_json(output)
    except AttributeError as e:
        socbuddy.error_message("Failed to parse HTML", e)
    chrome_extension_lookup() if socbuddy.ask_to_run_again() else menu()
