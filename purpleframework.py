#!/usr/bin/env python3

import webbrowser
import sys, signal
from colorama import Fore
import time
import subprocess

def def_handler(sig, frame):
    print(Fore.RED + "\n\n[!] QUITTING...\n\n")
    sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

def print_banner():
    banner = '''
        ╔═╗╦ ╦╦═╗╔═╗╦  ╔═╗╔═╗╦═╗╔═╗╔╦╗╔═╗╦ ╦╔═╗╦═╗╦╔═
        ╠═╝║ ║╠╦╝╠═╝║  ║╣ ╠╣ ╠╦╝╠═╣║║║║╣ ║║║║ ║╠╦╝╠╩╗
        ╩  ╚═╝╩╚═╩  ╩═╝╚═╝╚  ╩╚═╩ ╩╩ ╩╚═╝╚╩╝╚═╝╩╚═╩ ╩
      ╚═════════════ 𝓟 𝓤 𝓡 𝓟 𝓛 𝓔 𝓓 𝓔 𝓥 ═════════════╝
    '''
    print(Fore.LIGHTMAGENTA_EX + banner + Fore.RESET)
	
main_menu = '''
    [01] Attack surfaces
    [02] Business
    [03] Codes
    [04] Cyberthreats
    [05] Domains
    [06] Emails
    [07] Search engines
    [08] Frameworks
    [09] Images
    [10] Internet
    [11] IP address
    [12] Market / Stock / Crypto
    [13] Phone numbers
    [14] Social media OSINT
    [15] Steganography
    [16] Tracking
    [17] Transport
    [18] Penetration testing
'''
	
print_banner()
print(main_menu)
category = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> ")

if category == "1":
    print("\n    Attack surfaces\n")
    print("    [01] Dwm")
    print("    [02] Discord")
    print("    [03] Email")
    print("    [04] FullHunt.io")
    print("    [05] Gab")
    print("    [06] Gettr")
    print("    [07] GitHub")
    print("    [08] Image")
    print("    [09] Instagram")
    print("    [10] IP")
    print("    [11] Mastodon")
    print("    [12] OpenSea")
    print("    [13] Person")
    print("    [14] Phone")
    print("    [15] Pinterest")
    print("    [16] Pokemon Go")
    print("    [17] Reddit")
    print("    [18] Skype")
    print("    [19] Snapchat")
    print("    [20] TikTok")
    print("    [21] Tumblr")
    print("    [22] Twitter")
    print("    [23] Username")
    print("    [24] Website")
    print("    [25] YouTube")
    
    att_surface = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Attack surfaces" + Fore.RESET + " >> ")
    
    if att_surface == '1':
        webbrowser.open("https://www.osintdojo.com/diagrams/dwm")
    elif att_surface == '2':
        webbrowser.open("https://www.osintdojo.com/diagrams/discord")
    elif att_surface == '3':
        webbrowser.open("https://www.osintdojo.com/diagrams/email")
    elif att_surface == '4':
        webbrowser.open("https://fullhunt.io/")
    elif att_surface == '5':
        webbrowser.open("https://www.osintdojo.com/diagrams/gab")
    elif att_surface == '6':
        webbrowser.open("https://www.osintdojo.com/diagrams/gettr")
    elif att_surface == '7':
        webbrowser.open("https://www.osintdojo.com/diagrams/github")
    elif att_surface == '8':
        webbrowser.open("https://www.osintdojo.com/diagrams/image")
    elif att_surface == '9':
        webbrowser.open("https://www.osintdojo.com/diagrams/instagram")
    elif att_surface == '10':
        webbrowser.open("https://www.osintdojo.com/diagrams/ip")
    elif att_surface == '11':
        webbrowser.open("https://www.osintdojo.com/diagrams/mastodon")
    elif att_surface == '12':
        webbrowser.open("https://www.osintdojo.com/diagrams/opensea")
    elif att_surface == '13':
        webbrowser.open("https://www.osintdojo.com/diagrams/person")
    elif att_surface == '14':
        webbrowser.open("https://www.osintdojo.com/diagrams/phone")
    elif att_surface == '15':
        webbrowser.open("https://www.osintdojo.com/diagrams/pinterest")
    elif att_surface == '16':
        webbrowser.open("https://www.osintdojo.com/diagrams/pokemongo")
    elif att_surface == '17':
        webbrowser.open("https://www.osintdojo.com/diagrams/reddit")
    elif att_surface == '18':
        webbrowser.open("https://www.osintdojo.com/diagrams/skype")
    elif att_surface == '19':
        webbrowser.open("https://www.osintdojo.com/diagrams/snapchat")
    elif att_surface == '20':
        webbrowser.open("https://www.osintdojo.com/diagrams/tiktok")
    elif att_surface == '21':
        webbrowser.open("https://www.osintdojo.com/diagrams/tumblr")
    elif att_surface == '22':
        webbrowser.open("https://www.osintdojo.com/diagrams/twitter")
    elif att_surface == '23':
        webbrowser.open("https://www.osintdojo.com/diagrams/username")
    elif att_surface == '24':
        webbrowser.open("https://www.osintdojo.com/diagrams/website")
    elif att_surface == '25':
        webbrowser.open("https://www.osintdojo.com/diagrams/youtube")
    else:
        print("Select valid option...")

elif category == "2":
    print("\n    Business OSINT\n")
    print("    [01] Axesor")
    print("    [02] eInforma")
    print("    [03] Company Searches CN")
    print("    [04] Registration China")
    print("    [05] Colorado Secretary of State")
    print("    [06] Companies House (UK)")
    print("    [07] Company Check")
    print("    [08] German Trade Register")
    print("    [09] Endole")
    print("    [10] System Day")
    print("    [11] Iberinform")
    print("    [12] Informa")
    print("    [13] EmpresaSite")
    print("    [14] European Business Register")
    print("    [15] Companies House (UK)")
    print("    [16] Gov.uk")
    print("    [17] Georgia Secretary of State")
    print("    [18] Infoempresa")
    print("    [19] Universia")
    print("    [20] Corporation Directory")
    print("    [21] European Business Register")
    print("    [22] Bundesanzeiger")
    print("    [23] Business France")
    print("    [24] California Business Search")
    print("    [25] Sirene (France)")
    
    business = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Business OSINT" + Fore.RESET + " >> ")

    if business == '1':
        webbrowser.open("https://www.axesor.es/buscador-empresas.aspx")
    elif business == '2':
        webbrowser.open("https://www.einforma.com/buscador-empresas")
    elif business == '3':
        webbrowser.open("https://companysearches.cn/")
    elif business == '4':
        webbrowser.open("https://www.registrationchina.com/china-company-search/")
    elif business == '5':
        webbrowser.open("https://www.sos.state.co.us/biz/BusinessEntityCriteriaExt.do")
    elif business == '6':
        webbrowser.open("https://www.gov.uk/government/organisations/companies-house")
    elif business == '7':
        webbrowser.open("https://companycheck.co.uk/")
    elif business == '8':
        webbrowser.open("https://www.unternehmensregister.de/ureg/?submitaction=language&language=en")
    elif business == '9':
        webbrowser.open("https://www.endole.co.uk/products/company-search/")
    elif business == '10':
        webbrowser.open("https://www.systemday.com/company-searches/")
    elif business == '11':
        webbrowser.open("https://www.iberinform.es/informacion-de-empresas")
    elif business == '12':
        webbrowser.open("https://www.informa.es/directorio-empresas")
    elif business == '13':
        webbrowser.open("https://empresite.eleconomista.es/")
    elif business == '14':
        webbrowser.open("https://e-justice.europa.eu/106/EN/business_registers_in_eu_countries?FRANCE&member=1")
    elif business == '15':
        webbrowser.open("https://wck2.companieshouse.gov.uk//wcframe?name=accessCompanyInfo")
    elif business == '16':
        webbrowser.open("https://find-and-update.company-information.service.gov.uk/")
    elif business == '17':
        webbrowser.open("https://ecorp.sos.ga.gov/BusinessSearch")
    elif business == '18':
        webbrowser.open("https://www.infoempresa.com/es-es/es/buscador-de-empresas")
    elif business == '19':
        webbrowser.open("https://guiaempresas.universia.es/")
    elif business == '20':
        webbrowser.open("https://corporation.directory/quicksearch/company")
    elif business == '21':
        webbrowser.open("https://e-justice.europa.eu/home?action=home&plang=es")
    elif business == '22':
        webbrowser.open("https://www.bundesanzeiger.de/reg/en/account/registration-start?0")
    elif business == '23':
        webbrowser.open("https://www.businessfrance.fr/en/search")
    elif business == '24':
        webbrowser.open("https://bizfileonline.sos.ca.gov/search/business")
    elif business == '25':
        webbrowser.open("https://www.info-clipper.com/en/")
    else:
        print("Select valid option...")

elif category == "3":
    print("\n    Codes and cyphers\n")
    print("    [01] Online Barcode Reader")
    print("    [02] Base64 Decode")
    print("    [03] Caesar Cipher Decoder")
    print("    [04] Cognex Barcode Scanner")
    print("    [05] Nanonets Barcode Scanner")
    print("    [06] QR Code Online Reader")
    print("    [07] Aspose Barcode Recognizer (QR)")
    print("    [08] Aspose Barcode Scanner (No Camera)")
    print("    [09] Pigpen Cipher Decoder")
    print("    [10] Aspose Barcode Recognizer")
    print("    [11] ROT13 Decoder")
    print("    [12] String and Word Frequency Analyzer")

    codes = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Codes and cyphers" + Fore.RESET + " >> " + Style.BRIGHT)

    if codes == '1':
        webbrowser.open("https://online-barcode-reader.inliteresearch.com/")
    elif codes == '2':
        webbrowser.open("https://www.base64decode.org/")
    elif codes == '3':
        webbrowser.open("https://www.dcode.fr/caesar-cipher")
    elif codes == '4':
        webbrowser.open("https://cmbdn.cognex.com/free-barcode-scanner")
    elif codes == '5':
        webbrowser.open("https://nanonets.com/barcode-scanner")
    elif codes == '6':
        webbrowser.open("https://www.codigos-qr.com/lector-qr-online/")
    elif codes == '7':
        webbrowser.open("https://products.aspose.app/barcode/es/recognize/qr")
    elif codes == '8':
        webbrowser.open("https://products.aspose.app/barcode/scan#/nocamera")
    elif codes == '9':
        webbrowser.open("https://www.boxentriq.com/code-breaking/pigpen-cipher")
    elif codes == '10':
        webbrowser.open("https://products.aspose.app/barcode/recognize")
    elif codes == '11':
        webbrowser.open("https://cryptii.com/pipes/rot13-decoder")
    elif codes == '12':
        webbrowser.open("https://scwf.dima.ninja/")
    else:
        print("Select valid option...")

elif category == "4":
    print("\n    CYBERTHREAT\n")
    print("    [1] Bitdefender Threat Map")
    print("    [2] FortiGuard Threat Map")
    print("    [3] Radware Live Threat Map")
    print("    [4] Check Point Threat Map")
    print("    [5] Kaspersky Cyber Map")

    cyberthreat = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Cyberthreat" + Fore.RESET + " >> " + Style.BRIGHT)

    if cyberthreat == '1':
        webbrowser.open("https://threatmap.bitdefender.com/")
    elif cyberthreat == '2':
        webbrowser.open("https://threatmap.fortiguard.com/")
    elif cyberthreat == '3':
        webbrowser.open("https://livethreatmap.radware.com/")
    elif cyberthreat == '4':
        webbrowser.open("https://threatmap.checkpoint.com/")
    elif cyberthreat == '5':
        webbrowser.open("https://cybermap.kaspersky.com/")
    else:
        print("Select valid option.")

elif category == "5":
    print("\n    Domain OSINT")
    print("    [01] CompleteDNS - DNS History")
    print("    [02] DNS Leak Test")
    print("    [03] NSLookup.io")
    print("    [04] Red Sift - OnDomain Investigation")
    print("    [05] Domain Investigation Toolbox")
    print("    [06] ExpandURL")
    print("    [07] Tiny Scan")
    print("    [08] Netcraft Tools")
    print("    [09] URLScan.io")
    print("    [10] Urlex.org")
    print("    [11] VirusTotal")
    print("    [12] Web Check")
    print("    [13] Whois Lookup")

    domains = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Domain OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if domains == '1':
        webbrowser.open("https://completedns.com/dns-history/")
    elif domains == '2':
        webbrowser.open("https://www.dnsleaktest.com/")
    elif domains == '3':
        webbrowser.open("https://www.nslookup.io/")
    elif domains == '4':
        webbrowser.open("https://redsift.com/products/ondomain/investigation")
    elif domains == '5':
        webbrowser.open("https://cipher387.github.io/domain_investigation_toolbox/")
    elif domains == '6':
        webbrowser.open("https://www.expandurl.net/expand/")
    elif domains == '7':
        webbrowser.open("https://www.tiny-scan.com/")
    elif domains == '8':
        webbrowser.open("https://www.netcraft.com/tools/")
    elif domains == '9':
        webbrowser.open("https://urlscan.io/")
    elif domains == '10':
        webbrowser.open("https://urlex.org/")
    elif domains == '11':
        webbrowser.open("https://www.virustotal.com/gui/home/upload")
    elif domains_ == '12':
        webbrowser.open("https://web-check.as93.net/")
    elif domains == '13':
        webbrowser.open("https://who.is/")
    else:
        print("Select valid option.")

elif category == "6":
    print("\n    Email OSINT\n")
    print("    [01] That's Them - Reverse Email Lookup")
    print("    [02] Proofy.io")
    print("    [03] CentralOps - Email Dossier")
    print("    [04] Voila Norbert")
    print("    [05] RecordsFinder - Email Search")
    print("    [06] Email Temporal Gratis")
    print("    [07] EmailVeritas")
    print("    [08] EPIEOS")
    print("    [09] Hunter.io")
    print("    [10] Find That Email")
    print("    [11] AnyMailFinder")
    print("    [12] Spytox - Reverse Email Lookup (Yahoo)")
    print("    [13] InfoTracer - Email Lookup")
    print("    [14] RocketReach")
    print("    [15] Anonymous Email")
    print("    [16] WhatIsMyIPAddress - Trace Email")
    print("    [17] Exposed.LOL")

    email = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Email OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if email == '1':
        webbrowser.open("https://thatsthem.com/challenge?r=%2Freverse-email-lookup")
    elif email == '2':
        webbrowser.open("https://proofy.io/")
    elif email == '3':
        webbrowser.open("https://centralops.net/co/emaildossier.aspx")
    elif email == '4':
        webbrowser.open("https://www.voilanorbert.com/")
    elif email == '5':
        webbrowser.open("https://www.recordsfinder.com/email/")
    elif email == '6':
        webbrowser.open("https://www.emailtemporalgratis.com/#/einrot.com/Imed1930/")
    elif email == '7':
        webbrowser.open("https://www.emailveritas.com/")
    elif email == '8':
        webbrowser.open("https://epieos.com/")
    elif email == '9':
        webbrowser.open("https://hunter.io/")
    elif email == '10':
        webbrowser.open("https://findthat.email/")
    elif email == '11':
        webbrowser.open("https://anymailfinder.com/")
    elif email == '12':
        webbrowser.open("https://www.spytox.com/reverse-email-lookup-yahoo")
    elif email == '13':
        webbrowser.open("https://infotracer.com/email-lookup/")
    elif email == '14':
        webbrowser.open("https://rocketreach.co/")
    elif email == '15':
        webbrowser.open("https://anonymousemail.me/")
    elif email == '16':
        webbrowser.open("https://whatismyipaddress.com/trace-email")
    elif email == '17':
        webbrowser.open("https://exposed.lol/")
    else:
        print("Select valid option.")

elif category == "7":
    print("\n    Search engines\n")
    print("    [01] Bing")
    print("    [02] Brave Search")
    print("    [03] Creative Commons Search")
    print("    [04] Criminal IP")
    print("    [05] DuckDuckGo")
    print("    [06] FOFA (Find Once Find All)")
    print("    [07] Gibiru")
    print("    [08] Wayback Machine (Internet Archive)")
    print("    [09] OneSearch")
    print("    [10] Search Encrypt")
    print("    [11] 192.com")
    print("    [12] Shodan Exploits")
    print("    [13] Shodan")
    print("    [14] StartPage")
    print("    [15] Swisscows")
    print("    [16] Web Check")
    print("    [17] Wiki.com")
    print("    [18] Yahoo Consent (Privacy-focused search)")
    print("    [19] Yandex")

    search_engines = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Search engines" + Fore.RESET + " >> " + Style.BRIGHT)

    if search_engines == '1':
        webbrowser.open("https://www.bing.com/")
    elif search_engines == '2':
        webbrowser.open("https://search.brave.com/")
    elif search_engines == '3':
        webbrowser.open("https://search.creativecommons.org/")
    elif search_engines == '4':
        webbrowser.open("https://www.criminalip.io/")
    elif search_engines == '5':
        webbrowser.open("https://duckduckgo.com/")
    elif search_engines == '6':
        webbrowser.open("https://en.fofa.info/")
    elif search_engines == '7':
        webbrowser.open("https://gibiru.com/")
    elif search_engines == '8':
        webbrowser.open("https://archive.org/web/")
    elif search_engines == '9':
        webbrowser.open("https://www.onesearch.com/")
    elif search_engines == '10':
        webbrowser.open("https://www.searchencrypt.com/home")
    elif search_engines == '11':
        webbrowser.open("https://www.192.com/")
    elif search_engines == '12':
        webbrowser.open("https://exploits.shodan.io/welcome")
    elif search_engines == '13':
        webbrowser.open("https://www.shodan.io/")
    elif search_engines == '14':
        webbrowser.open("https://www.startpage.com/es/")
    elif search_engines == '15':
        webbrowser.open("https://swisscows.com/es")
    elif search_engines == '16':
        webbrowser.open("https://web-check.xyz/")
    elif search_engines == '17':
        webbrowser.open("https://wiki.com/")
    elif search_engines == '18':
        webbrowser.open("https://consent.yahoo.com/v2/collectConsent?sessionId=3_cc-session_c7ede585-7b14-4bea-a392-ab5c4dc291ff")
    elif search_engines == '19':
        webbrowser.open("https://yandex.com/")
    else:
        print("Select valid option.")

elif category == "8":
    print("\n    Frameworks\n")
    print("    [01] Brigada OSINT")
    print("    [02] Intelligence X")
    print("    [03] Lampyre")
    print("    [04] Netlas")
    print("    [05] OS-Surveillance")
    print("    [06] OSINT Combine")
    print("    [07] OSINT Dojo - Tools")
    print("    [08] OSINT Framework")
    print("    [09] OSINT Industries")
    print("    [10] OS2INT Toolbox")
    print("    [11] HowToFind OSINT Tools")
    print("    [12] AWARE Online")
    print("    [13] OSINT.sh")
    print("    [14] OSINT Curious")
    print("    [15] OSINT Geek")
    print("    [16] Kamerka")
    print("    [17] ZoomEye")

    frameworks = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Frameworks" + Fore.RESET + " >> " + Style.BRIGHT)

    if frameworks == '1':
        webbrowser.open("https://www.brigadaosint.com/")
    elif frameworks == '2':
        webbrowser.open("https://intelx.io/")
    elif frameworks == '3':
        webbrowser.open("https://lampyre.io/")
    elif frameworks == '4':
        webbrowser.open("https://app.netlas.io/host/")
    elif frameworks == '5':
        webbrowser.open("https://www.os-surveillance.io/")
    elif frameworks == '6':
        webbrowser.open("https://www.osintcombine.com/tools")
    elif frameworks == '7':
        webbrowser.open("https://www.osintdojo.com/resources/")
    elif frameworks == '8':
        webbrowser.open("https://osintframework.com/")
    elif frameworks == '9':
        webbrowser.open("https://osint.industries/")
    elif frameworks == '10':
        webbrowser.open("https://os2int.com/toolbox/")
    elif frameworks == '11':
        webbrowser.open("https://github.com/HowToFind-bot/osint-tools")
    elif frameworks == '12':
        webbrowser.open("https://www.aware-online.com/en/")
    elif frameworks == '13':
        webbrowser.open("https://osint.sh/")
    elif frameworks == '14':
        webbrowser.open("https://www.osintcurio.us/")
    elif frameworks == '15':
        webbrowser.open("https://osintgeek.de/tools")
    elif frameworks == '16':
        webbrowser.open("https://www.kamerka.io/")
    elif frameworks == '17':
        webbrowser.open("https://www.zoomeye.org/")
    else:
        print("Select valid option.")

elif category == "9":
    print("\n    Image OSINT\n")
    print("    [01] Facecheck.id")
    print("    [02] Labnol - Reverse Image Search")
    print("    [03] GeoSpy")
    print("    [04] GEO Estimation")
    print("    [05] Hugging Face - Kosmos-2")
    print("    [06] Img2Go - Rotate Image")
    print("    [07] Pic2Map")
    print("    [08] Picarta AI")
    print("    [09] PimEyes")
    print("    [10] Duplichecker - Reverse Image Search")
    print("    [11] ReverseImage.net")
    print("    [12] SmallSEOTools - Reverse Image Search")
    print("    [13] TinEye")
    print("    [14] VerExif")
    print("    [15] Where is the Picture")

    image_osint = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Image OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if image_osint == '1':
        webbrowser.open("https://facecheck.id/")
    elif image_osint == '2':
        webbrowser.open("https://www.labnol.org/reverse/")
    elif image_osint == '3':
        webbrowser.open("https://geospy.web.app/")
    elif image_osint == '4':
        webbrowser.open("https://labs.tib.eu/geoestimation/")
    elif image_osint == '5':
        webbrowser.open("https://huggingface.co/spaces/ydshieh/Kosmos-2")
    elif image_osint == '6':
        webbrowser.open("https://www.img2go.com/rotate-image")
    elif image_osint == '7':
        webbrowser.open("https://www.pic2map.com/")
    elif image_osint == '8':
        webbrowser.open("https://picarta.ai/")
    elif image_osint == '9':
        webbrowser.open("https://pimeyes.com/en")
    elif image_osint == '10':
        webbrowser.open("https://www.duplichecker.com/reverse-image-search.php")
    elif image_osint == '11':
        webbrowser.open("https://reverseimage.net/")
    elif image_osint == '12':
        webbrowser.open("https://smallseotools.com/reverse-image-search/")
    elif image_osint == '13':
        webbrowser.open("https://tineye.com/")
    elif image_osint == '14':
        webbrowser.open("https://www.verexif.com/")
    elif image_osint == '15':
        webbrowser.open("https://whereisthepicture.com/")
    else:
        print("Select valid option.")

elif category == "10":
    print("\n    Internet\n")
    print("    [01] Nmap")
    print("    [02] SSL Blacklist - JA3 Fingerprints")
    print("    [03] SSL Blacklist - SSL Certificates")
    print("    [04] What3words")
    print("    [05] WiGLE.net")

    internet_osint = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Internet" + Fore.RESET + " >> " + Style.BRIGHT)

    if internet_osint == '1':
        webbrowser.open("https://nmap.org/")
    elif internet_osint == '2':
        webbrowser.open("https://sslbl.abuse.ch/ja3-fingerprints/")
    elif internet_osint == '3':
        webbrowser.open("https://sslbl.abuse.ch/ssl-certificates/")
    elif internet_osint == '4':
        webbrowser.open("https://what3words.com/encontr%C3%B3.molida.mote")
    elif internet_osint == '5':
        webbrowser.open("https://www.wigle.net/")
    else:
        print("Select valid option.")

elif category == "11":
    print("\n    IP OSINT\n")
    print("    [01] AbuseIPDB")
    print("    [02] NordVPN - IP Lookup")
    print("    [03] IPLogger")
    print("    [04] MAC Vendors")
    print("    [05] IMEI24")
    print("    [06] IMEI.info")
    print("    [07] InfoByIP")
    print("    [08] WhatIsMyIP - IP Address Lookup")
    print("    [09] IPWhois.io")
    print("    [10] HackerTarget - GeoIP IP Location Lookup")
    print("    [11] IPLogger")
    print("    [12] Grabify")
    print("    [13] Arul John - MAC Address Lookup")
    print("    [14] DNS Checker - MAC Lookup")
    print("    [15] MAC-Address-AllDataFeeds - MAC Address Lookup")
    print("    [16] NSLookup.io - Reverse IP Lookup")
    print("    [17] DomainTools - Reverse IP Lookup")
    print("    [18] YouGetSignal - Web Sites on Web Server")
    print("    [19] MX Toolbox - Reverse Lookup")
    print("    [20] DNS Checker - Reverse DNS Lookup")
    print("    [21] Zoho Toolkit - Reverse Lookup")
    print("    [22] HackerTarget - Reverse IP Lookup")
    print("    [23] IPinfo.io")
    print("    [24] IKnowWhatYouDownload - Peer Lookup")
    print("    [25] IMEI.info")
    print("    [26] WhatIsMyIPAddress.com")
    print("    [27] DomainTools - Whois Lookup")

    ip_osint = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "IP OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if ip_osint == '1':
        webbrowser.open("https://www.abuseipdb.com/")
    elif ip_osint == '2':
        webbrowser.open("https://nordvpn.com/es/ip-lookup/")
    elif ip_osint == '3':
        webbrowser.open("https://iplogger.org/es/signup/")
    elif ip_osint == '4':
        webbrowser.open("https://macvendors.com/")
    elif ip_osint == '5':
        webbrowser.open("https://imei24.com/")
    elif ip_osint == '6':
        webbrowser.open("https://www.imei.info/?imei=352602081794916")
    elif ip_osint == '7':
        webbrowser.open("https://www.infobyip.com/")
    elif ip_osint == '8':
        webbrowser.open("https://www.whatismyip.com/ip-address-lookup/")
    elif ip_osint == '9':
        webbrowser.open("https://ipwhois.io/")

elif category == "12":
    print("\n    Market\n")
    print("    [01] Investing.com - Bitcoin Historical Data")
    print("    [02] CoinMarketCap - Historical Data")
    print("    [03] MacroTrends - Euro to Dollar Exchange Rate")
    print("    [04] Investing.com - GBP to EUR Historical Data")
    print("    [05] Wall Street Journal - GBP to USD Historical Prices")
    print("    [06] OANDA - Historical Currency Converter")
    print("    [07] Investing.com")
    print("    [08] Investing.com - USDollar Historical Data")

    market_osint = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Market/stock OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if market_osint == '1':
        webbrowser.open("https://www.investing.com/crypto/bitcoin/historical-data")
    elif market_osint == '2':
        webbrowser.open("https://coinmarketcap.com/historical/")
    elif market_osint == '3':
        webbrowser.open("https://www.macrotrends.net/2548/euro-dollar-exchange-rate-historical-chart")
    elif market_osint == '4':
        webbrowser.open("https://www.investing.com/currencies/gbp-eur-historical-data")
    elif market_osint == '5':
        webbrowser.open("https://www.wsj.com/market-data/quotes/fx/GBPUSD/historical-prices")
    elif market_osint == '6':
        webbrowser.open("https://fxds-hcc.oanda.com/")
    elif market_osint == '7':
        webbrowser.open("https://www.investing.com/")
    elif market_osint == '8':
        webbrowser.open("https://www.investing.com/indices/usdollar-historical-data")
    else:
        print("Select valid option.")

elif category == "13":
    print("\n    Phone OSINT\n")
    print("    [01] CountryCode.org")
    print("    [02] SpyDialer")
    print("    [03] Truecaller - Reverse Phone Number Lookup")
    print("    [04] Martin Vigo - Phonerator")
    print("    [05] Temporary Phone Number - UK")
    print("    [06] Temporary Phone Number")
    print("    [07] NumLookup")
    print("    [08] Spokeo - Reverse Phone Lookup")
    print("    [09] FreePhoneNum - Send Text")
    print("    [10] TextNow")

    phone_osint = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Phone numbers OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if phone_osint == '1':
        webbrowser.open("https://countrycode.org/")
    elif phone_osint == '2':
        webbrowser.open("https://www.spydialer.com/")
    elif phone_osint == '3':
        webbrowser.open("https://www.truecaller.com/reverse-phone-number-lookup")
    elif phone_osint == '4':
        webbrowser.open("https://www.martinvigo.com/tools/phonerator/")
    elif phone_osint == '5':
        webbrowser.open("https://temporary-phone-number.com/UK-Phone-Number/447893920086")
    elif phone_osint == '6':
        webbrowser.open("https://es.temporary-phone-number.com/")
    elif phone_osint == '7':
        webbrowser.open("https://www.numlookup.com/")
    elif phone_osint == '8':
        webbrowser.open("https://www.spokeo.com/reverse-phone-lookup")
    elif phone_osint == '9':
        webbrowser.open("https://es.freephonenum.com/send-text")
    elif phone_osint == '10':
        webbrowser.open("https://www.textnow.com/")
    else:
        print("Select valid option.")

elif category == "14":
    print("\n    SOCMINT - Social Media OSINT\n")
    print("    [01] OctoSniff - Beta")
    print("    [02] Blackbird OSINT")
    print("    [03] Mattw.io - YouTube Geofind")
    print("    [04] CheckUsernames.com")
    print("    [05] Lookup ID")
    print("    [06] UserSearch.org")
    print("    [07] Foller.me")
    print("    [08] Fake Name Generator")
    print("    [09] OSINT Combine - Instagram Explorer")
    print("    [10] Picuki")
    print("    [11] Instant Username")
    print("    [12] Just Delete Me")
    print("    [13] JustGetMyData")
    print("    [14] Lancremastered PCPS")
    print("    [15] Mattw.io - YouTube Metadata")
    print("    [16] Namecheckr")
    print("    [17] NameChk")
    print("    [18] Seintpl - NAMINT")
    print("    [19] One-Plus - Youtube")
    print("    [20] PeekYou")
    print("    [21] PeopleFindThor.dk")
    print("    [22] SearchIsBack")
    print("    [23] Social Searcher")
    print("    [24] SowSearch")
    print("    [25] Spokeo - Social Profile")
    print("    [26] StalkFace")
    print("    [27] OSINT Combine - TikTok Quick Search")
    print("    [28] Tinfoleak")
    print("    [29] TweeterID")
    print("    [30] Social Bearing")
    print("    [31] Uncovered - Social Media Checklist")
    print("    [32] WhatsMyName")
    print("    [33] WhoPostedWhat")
    print("    [34] XResolver - PlayStation")
    print("    [35] Social Blade")

    socmint_osint = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "SOCMINT - Social Media OSINT" + Fore.RESET + " >> " + Style.BRIGHT)

    if socmint_osint == '1':
        webbrowser.open("https://beta.octosniff.net/auth?security=b736c400")
    elif socmint_osint == '2':
        webbrowser.open("https://blackbird-osint.herokuapp.com/")
    elif socmint_osint == '3':
        webbrowser.open("https://mattw.io/youtube-geofind/")
    elif socmint_osint == '4':
        webbrowser.open("https://checkusernames.com/")
    elif socmint_osint == '5':
        webbrowser.open("https://lookup-id.com/")
    elif socmint_osint == '6':
        webbrowser.open("https://usersearch.org/")
    elif socmint_osint == '7':
        webbrowser.open("https://foller.me/")
    elif socmint_osint == '8':
        webbrowser.open("https://www.fakenamegenerator.com/advanced.php?t=country&n%5B%5D=sp&c%5B%5D=sp&gen=20&age-min=19&age-max=40")
    elif socmint_osint == '9':
        webbrowser.open("https://www.osintcombine.com/instagram-explorer")
    elif socmint_osint == '10':
        webbrowser.open("https://www.picuki.com/")
    elif socmint_osint == '11':
        webbrowser.open("https://instantusername.com/#/")
    elif socmint_osint == '12':
        webbrowser.open("https://backgroundchecks.org/justdeleteme/es.html")
    elif socmint_osint == '13':
        webbrowser.open("https://justgetmydata.com/")
    elif socmint_osint == '14':
        webbrowser.open("https://lancremasteredpcps.com/")
    elif socmint_osint == '15':
        webbrowser.open("https://mattw.io/youtube-metadata/")
    elif socmint_osint == '16':
        webbrowser.open("https://www.namecheckr.com/")
    elif socmint_osint == '17':
        webbrowser.open("https://namechk.com/")
    elif socmint_osint == '18':
        webbrowser.open("https://seintpl.github.io/NAMINT/")
    elif socmint_osint == '19':
        webbrowser.open("https://one-plus.github.io/Youtube")
    elif socmint_osint == '20':
        webbrowser.open("https://www.peekyou.com/")
    elif socmint_osint == '21':
        webbrowser.open("https://peoplefindthor.dk/")
    elif socmint_osint == '22':
        webbrowser.open("https://searchisback.com/")
    elif socmint_osint == '23':
        webbrowser.open("https://www.social-searcher.com/")
    elif socmint_osint == '24':
        webbrowser.open("https://www.sowsearch.info/")
    elif socmint_osint == '25':
        webbrowser.open("https://www.spokeo.com/social/profile?q=rodrigo")
    elif socmint_osint == '26':
        webbrowser.open("https://stalkface.com/es/")
    elif socmint_osint == '27':
        webbrowser.open("https://www.osintcombine.com/tiktok-quick-search")
    elif socmint_osint == '28':
        webbrowser.open("https://tinfoleak.com/")
    elif socmint_osint == '29':
        webbrowser.open("https://tweeterid.com/")
    elif socmint_osint == '30':
        webbrowser.open("https://socialbearing.com/")
    elif socmint_osint == '31':
        webbrowser.open("https://uncovered.com/a-checklist-for-gathering-info-on-social-media/")
    elif socmint_osint == '32':
        webbrowser.open("https://whatsmyname.app/")
    elif socmint_osint == '33':
        webbrowser.open("https://whopostedwhat.com/")
    elif socmint_osint == '34':
        webbrowser.open("https://xresolver.com/playstation")
    elif socmint_osint == '35':
        webbrowser.open("https://socialblade.com/")
    else:
        print("Select valid option.")

elif category == "15":
    print("\n    Steganography\n")
    print("    [01] AperiSolve")
    print("    [02] Stylesuxx - Steganography")
    print("    [03] StegOnline")

    steganography = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "Steganography" + Fore.RESET + " >> " + Style.BRIGHT)

    if steganography == '1':
        webbrowser.open("https://www.aperisolve.com/")
    elif steganography == '2':
        webbrowser.open("https://stylesuxx.github.io/steganography/")
    elif steganography == '3':
        webbrowser.open("https://stegonline.georgeom.net/upload")
    else:
        print("Select valid option.")

elif category == "16":
    print("\n    TRACKING\n")
    print("    [01] Air and Space Tracking")
    print("    [02] Camera Tracking")
    print("    [03] Land and Sea Tracking")
    print("    [04] Wildlife Tracking")

    tracking = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "TRACKING" + Fore.RESET + " >> " + Style.BRIGHT)

    if tracking == '1':
        print("\n    AIR AND SPACE TRACKING\n")
        print("    [01] In The Sky - Satellite World Map")
        print("    [02] Esri - Space Satellite Explorer")
        print("    [03] Satellite Map")
        print("    [04] Amateur SondeHub")
        print("    [05] Airportia")
        print("    [06] RadarBox")
        print("    [07] FlightAware")
        print("    [08] ADS-B Exchange Globe")
        print("    [09] Plane Finder")
        print("    [10] Flightradar Live")
        print("    [11] Flightradar24")

        air_space_tracking = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "AIR AND SPACE TRACKING" + Fore.RESET + " >> " + Style.BRIGHT)

        if air_space_tracking == '1':
            webbrowser.open("https://in-the-sky.org/satmap_worldmap.php")
        elif air_space_tracking == '2':
            webbrowser.open("https://geoxc-apps.bd.esri.com/space/satellite-explorer/")
        elif air_space_tracking == '3':
            webbrowser.open("https://satellitemap.space/")
        elif air_space_tracking == '4':
            webbrowser.open("https://amateur.sondehub.org/")
        elif air_space_tracking == '5':
            webbrowser.open("https://www.airportia.com/")
        elif air_space_tracking == '6':
            webbrowser.open("https://www.radarbox.com/")
        elif air_space_tracking == '7':
            webbrowser.open("https://www.flightaware.com/live/")
        elif air_space_tracking == '8':
            webbrowser.open("https://globe.adsbexchange.com/")
        elif air_space_tracking == '9':
            webbrowser.open("https://planefinder.net/")
        elif air_space_tracking == '10':
            webbrowser.open("https://flightradar.live/")
        elif air_space_tracking == '11':
            webbrowser.open("https://www.flightradar24.com/40.49,-3.88/6")
        else:
            print("Select valid option.")

    elif tracking == '2':
        print("\n    CAMERA TRACKING\n")
        print("    [01] Live from Iceland")
        print("    [02] Opentopia")
        print("    [03] WorldCam")
        print("    [04] Fisgonia")
        print("    [05] EarthCam")
        print("    [06] World Webcams")
        print("    [07] Insecam")

        camera_tracking = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "CAMERA TRACKING" + Fore.RESET + " >> " + Style.BRIGHT)

        if camera_tracking == '1':
            webbrowser.open("https://www.livefromiceland.is/")
        elif camera_tracking == '2':
            webbrowser.open("https://www.opentopia.com/hiddencam.php")
        elif camera_tracking == '3':
            webbrowser.open("https://worldcam.eu/")
        elif camera_tracking == '4':
            webbrowser.open("https://www.fisgonia.com/")
        elif camera_tracking == '5':
            webbrowser.open("https://www.earthcam.com/")
        elif camera_tracking == '6':
            webbrowser.open("https://world-webcams.nsspot.net/")
        elif camera_tracking == '7':
            webbrowser.open("https://www.insecam.org/")
        else:
            print("Select valid option.")

    elif tracking == '3':
        print("\n    LAND AND SEA TRACKING\n")
        print("    [01] Satellites Pro")
        print("    [02] Open Train Times")
        print("    [03] GEOPS - World Transit")
        print("    [04] Open Railway Map")

        land_sea_tracking = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "LAND AND SEA TRACKING" + Fore.RESET + " >> " + Style.BRIGHT)

        if land_sea_tracking == '1':
            webbrowser.open("https://satellites.pro/")
        elif land_sea_tracking == '2':
            webbrowser.open("https://www.opentraintimes.com/maps")
        elif land_sea_tracking == '3':
            webbrowser.open("https://mobility.portal.geops.io/en/world.geops.transit")
        elif land_sea_tracking == '4':
            webbrowser.open("https://www.openrailwaymap.org/")
        else:
            print("Select valid option.")

    elif tracking == '4':
        print("\n    WILDLIFE TRACKING\n")
        print("    [01] Movebank")
        print("    [02] OCEARCH Tracker")
        print("    [03] Explore - Live Cams")
        print("    [04] Africam - Wildlife")

        wildlife_tracking = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "WILDLIFE TRACKING" + Fore.RESET + " >> " + Style.BRIGHT)

        if wildlife_tracking == '1':
            webbrowser.open("https://www.movebank.org/cms/movebank-main")
        elif wildlife_tracking == '2':
            webbrowser.open("https://www.ocearch.org/tracker/")
        elif wildlife_tracking == '3':
            webbrowser.open("https://explore.org/livecams")
        elif wildlife_tracking == '4':
            webbrowser.open("https://www.africam.com/wildlife/")
        else:
            print("Select valid option.")

    else:
        print("Select valid option.")

elif category == "17":
    print("\n    TRANSPORT\n")
    print("    [01] AirlinersGallery - Airline Tails")
    print("    [02] Airliners.net")
    print("    [03] Airport Webcams")
    print("    [04] Platesmania - Search")
    print("    [05] Seisenlinea - Calculate Registration Date")
    print("    [06] Carnet AI")
    print("    [07] Vehicle Enquiry (UK)")
    print("    [08] Flight Connections")
    print("    [09] Platesmania")
    print("    [10] Vessel Finder")
    print("    [11] Find by Plate")
    print("    [12] Vehicle History - License Plate Search")
    print("    [13] Marine Traffic - AIS")
    print("    [14] Rail Cab Rides")
    print("    [15] AutoCheck - License Plate Search")
    print("    [16] VIN Audit")
    print("    [17] Skyscanner")
    print("    [18] NBI National Vehicle File - License Plate Inquiries")

    transport = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "TRANSPORT" + Fore.RESET + " >> " + Style.BRIGHT)

    if transport == '1':
        webbrowser.open("https://airlinersgallery.smugmug.com/Airline-Tails/Airline-Tails/")
    elif transport == '2':
        webbrowser.open("https://www.airliners.net/")
    elif transport == '3':
        webbrowser.open("https://airportwebcams.net/")
    elif transport == '4':
        webbrowser.open("https://platesmania.com/fr/search")
    elif transport == '5':
        webbrowser.open("https://www.seisenlinea.com/calcular-fecha-matriculacion/")
    elif transport == '6':
        webbrowser.open("https://carnet.ai/")
    elif transport == '7':
        webbrowser.open("https://vehicleenquiry.service.gov.uk/")
    elif transport == '8':
        webbrowser.open("https://www.flightconnections.com/")
    elif transport == '9':
        webbrowser.open("https://platesmania.com/")
    elif transport == '10':
        webbrowser.open("https://www.vesselfinder.com/")
    elif transport == '11':
        webbrowser.open("https://findbyplate.com/")
    elif transport == '12':
        webbrowser.open("https://www.vehiclehistory.com/license-plate-search")
    elif transport == '13':
        webbrowser.open("https://www.marinetraffic.com/en/ais/home/centerx:-12.0/centery:24.9/zoom:4")
    elif transport == '14':
        webbrowser.open("https://railcabrides.com/")
    elif transport == '15':
        webbrowser.open("https://www.autocheck.com/vehiclehistory/search-by-license-plate")
    elif transport == '16':
        webbrowser.open("https://www.vinaudit.com/")
    elif transport == '17':
        webbrowser.open("https://www.skyscanner.es/?previousCultureSource=GEO_LOCATION&redirectedFrom=www.skyscanner.net")
    elif transport == '18':
        webbrowser.open("https://www.nbi-ngf.ch/en/nvb/auskunftsstelle/kennzeichenanfragen")
    else:
        print("Select valid option.")

elif category == "18":
    print("\n    PENTESTING\n")
    print("    [01] CVE Details")
    print("    [02] CXSecurity")
    print("    [03] VulDB")
    print("    [04] Vulnerability Lab")
    print("    [05] WPScan - WordPresses")
    print("    [06] Patchstack Database")
    print("    [07] ArtToolkit")
    print("    [08] CrackStation")
    print("    [09] CyberChef")
    print("    [10] Exploit-DB")
    print("    [11] Cybrary")
    print("    [12] Hack The Box")
    print("    [13] NVD - National Vulnerability Database")
    print("    [14] OWASP")
    print("    [15] Packet Storm Security")
    print("    [16] Pentester Academy")
    print("    [17] Reddit - Netsec")
    print("    [18] TryHackMe")
    print("    [19] VulnHub")

    pentesting = input(Fore.LIGHTMAGENTA_EX + "\nPurpleframeworK" + Fore.RESET + " >> " + Fore.LIGHTMAGENTA_EX + "PENTESTING" + Fore.RESET + " >> " + Style.BRIGHT)

    if pentesting == '1':
        webbrowser.open("https://www.cvedetails.com/")
    elif pentesting == '2':
        webbrowser.open("https://cxsecurity.com/exploit/")
    elif pentesting == '3':
        webbrowser.open("https://vuldb.com/")
    elif pentesting == '4':
        webbrowser.open("https://www.vulnerability-lab.com/")
    elif pentesting == '5':
        webbrowser.open("https://wpscan.com/wordpresses")
    elif pentesting == '6':
        webbrowser.open("https://patchstack.com/database/")
    elif pentesting == '7':
        webbrowser.open("https://arttoolkit.github.io/")
    elif pentesting == '8':
        webbrowser.open("https://crackstation.net/")
    elif pentesting == '9':
        webbrowser.open("https://gchq.github.io/CyberChef/")
    elif pentesting == '10':
        webbrowser.open("https://www.exploit-db.com/")
    elif pentesting == '11':
        webbrowser.open("https://www.cybrary.it/")
    elif pentesting == '12':
        webbrowser.open("https://www.hackthebox.com/")
    elif pentesting == '13':
        webbrowser.open("https://nvd.nist.gov/")
    elif pentesting == '14':
        webbrowser.open("https://owasp.org/")
    elif pentesting == '15':
        webbrowser.open("https://packetstormsecurity.com/")
    elif pentesting == '16':
        webbrowser.open("https://www.pentesteracademy.com/")
    elif pentesting == '17':
        webbrowser.open("https://www.reddit.com/r/netsec/")
    elif pentesting == '18':
        webbrowser.open("https://tryhackme.com/")
    elif pentesting == '19':
        webbrowser.open("https://www.vulnhub.com/")
    else:
        print("Select valid option.")

else:
    print("Select valid option.")
