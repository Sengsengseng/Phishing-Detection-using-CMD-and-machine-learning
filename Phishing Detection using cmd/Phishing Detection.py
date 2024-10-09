'''
Necessary Python libraries and Initial setup
'''

# Necessary Python libraries
import colorama
from colorama import Fore, Style, Back
colorama.init()
import email
import re
import os
import sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from collections import Counter
import csv

# Additional Pre-processing Functions
print(Fore.MAGENTA)
print(Back.BLUE)
print(30 * "*", "Phishing Song Detector", 30 * "*")
print(Style.RESET_ALL+"")
test_path = input(Fore.BLUE + "Enter path of folder where mail is present: ").strip()

# Difference between two lists
def difference(first, second):
    second = set(second)
    for item in second:
        if item in first:
            first.remove(item)
    return first

# Counts the number of characters in a given string
def count_characters(string):
    return len(string) - string.count(' ') - string.count('\n')

def get_files(path):
    if os.path.exists(path) and os.path.isdir(path):
        return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and f.endswith('.eml')]
    else:
        raise ValueError(f"The specified path {path} is not a valid directory.")

def extract_msg(path, mail_file):
    # Check if the file has a .eml extension before processing it
    if not mail_file.endswith(".eml"):
        print(f"Skipping non-email file: {mail_file}")
        return None  # Return None explicitly to indicate the file was skipped

    mail_file = os.path.join(path, mail_file)
    try:
        with open(mail_file, "rb") as fp:
            mail_content = fp.read()
        return email.message_from_bytes(mail_content)
    except Exception as e:
        print(f"Error processing file {mail_file}: {e}")
        return None

# Extract the body from the message
def extract_body(msg):
    body_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" not in content_disposition:
                if content_type == "text/plain":
                    body_content += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == "text/html":
                    body_content += BeautifulSoup(part.get_payload(decode=True).decode('utf-8', errors='ignore'), 'html.parser').get_text()
    else:
        body_content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    return body_content if body_content.strip() else None

# Extract the subject from message
def extract_subj(msg):
    if msg['Subject']:
        decode_subj = email.header.decode_header(msg['Subject'])[0]
        try:
            subj_content = str(decode_subj[0], errors='ignore')
        except:
            subj_content = "None"
    else:
        subj_content = "None"
    return subj_content

# Extract sender address from message
def extract_send_address(msg):
    if msg['From']:
        decode_send = email.header.decode_header(msg['From'])[0]
        try:
            send_address = str(decode_send[0], errors='ignore')
        except:
            send_address = "None"
    else:
        send_address = "None"
    return send_address

# Extract reply-to address from message
def extract_replyTo_address(msg):
    if msg['Reply-To']:
        decode_replyTo = email.header.decode_header(msg['Reply-To'])[0]
        try:
            replyTo_address = str(decode_replyTo[0], errors='ignore')
        except:
            replyTo_address = "None"
    else:
        replyTo_address = "None"
    return replyTo_address

# Extract URLs from the email
def extract_urls(msg):
    mail = str(msg)
    urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", mail)
    return urls

# Extract anchor URLs from the email
def extract_anchor_urls(body_content):
    anchor_urls = []
    soup = BeautifulSoup(body_content, 'html.parser')
    for link in soup.findAll('a', attrs={'href': re.compile("^http[s]?://")}):
        anchor_urls.append(link.get('href'))
    return anchor_urls

# Extract all links
def extract_all_links(body_content):
    links = []
    soup = BeautifulSoup(body_content, 'html.parser')
    for link in soup.findAll('a'):
        links.append(link.get('href'))
    return links

# Extract necessary fields for email
def extract_necessary_fields(path, mail):
    msg = extract_msg(path, mail)
    if msg is None:
        print(f"Skipping mail due to failure in extraction: {mail}")
        return {}

    # Extract body content
    body_content = extract_body(msg)
    
    # Print the body content for debugging
    print(f"Extracted body for email {mail}: {body_content}")  
    
    necessary_fields = {
        'body': body_content,
        'subj': extract_subj(msg),
        'send': extract_send_address(msg),
        'replyTo': extract_replyTo_address(msg),
        'links': extract_all_links(body_content)
    }

    # Print links for debugging
    print(f"Extracted links for email {mail}: {necessary_fields.get('links', 'No Links Extracted')}")  
    
    return necessary_fields

# Define placeholder functions for extracting other features
def extract_body_attributes(body_content):
    return {
        'body_noWords': len(body_content.split()),
        'body_noCharacters': len(body_content),
        'body_richness': len(set(body_content.split())) / (len(body_content.split()) if len(body_content.split()) > 0 else 1),
    }

def extract_subj_attributes(subj_content):
    return {
        'subj_noWords': len(subj_content.split()),
        'subj_noCharacters': len(subj_content),
    }

def extract_send_attributes(send_address, replyTo_address, modal_url):
    return {
        'send_noWords': len(send_address.split()),
        'send_noCharacters': len(send_address),
    }

def extract_url_attributes(links, body_content, send_address, replyTo_address, modal_url):
    return {
        'url_noLinks': len(links),
    }

def extract_script_attributes(body_content, modal_url):
    return {
        'script_scripts': '<script>' in body_content,
    }
def extract_url_length(url):
    return len(url)

def extract_suspicious_characters(url):
    return int(any(c in url for c in ['@', '%', '//']))

def extract_header_attributes(headers):
    header_attributes = {
        'has_spf': int('spf' in headers.lower()),
        'has_dkim': int('dkim' in headers.lower()),
        'mismatch_sender_replyto': int(headers.get('From') != headers.get('Reply-To')) if headers.get('From') and headers.get('Reply-To') else 0
    }
    return header_attributes

suspicious_words = ['free', 'win', 'urgent', 'click here', 'money', 'limited', 'risk', 'account']

# Function to count suspicious words
def suspicious_word_count(text, suspicious_words):
    word_list = text.lower().split()
    return sum([word_list.count(word) for word in suspicious_words])

# Function to extract domain from URL
def extract_domain_from_url(url):
    try:
        return urlparse(url).netloc
    except:
        return ""
    

# Overall feature extraction
# Function to extract all the 40 features at once

def overall_feature_extraction(folder_path, mail_content, mail_file):
    necessary_fields = extract_necessary_fields(folder_path, mail_file)

    if "spam" in mail_file.lower():
        label = "spam"
    elif "ham" in mail_file.lower():
        label = "ham"
    else:
        print(f"Skipping non-email or unlabeled file: {mail_file}")
        return None

    # Extract features from different parts of the email
    body_attributes = extract_body_attributes(necessary_fields.get('body'))
    subj_attributes = extract_subj_attributes(necessary_fields.get('subj'))
    send_attributes = extract_send_attributes(
        necessary_fields.get('send'),
        necessary_fields.get('replyTo'),
        necessary_fields.get('modalURL', None)
    )
    url_attributes = extract_url_attributes(
        necessary_fields.get('links'),
        necessary_fields.get('body'),
        necessary_fields.get('send'),
        necessary_fields.get('replyTo'),
        necessary_fields.get('modalURL', None)
    )
    script_attributes = extract_script_attributes(necessary_fields.get('body'), necessary_fields.get('modalURL', None))

    # Combine new URL length and suspicious character features
    features = {}
    features.update(body_attributes)
    features.update(subj_attributes)
    features.update(send_attributes)
    features.update(url_attributes)
    features.update(script_attributes)
    features['url_length'] = extract_url_length(necessary_fields['links'][0]) if necessary_fields['links'] else 0
    features['suspicious_characters'] = extract_suspicious_characters(necessary_fields['links'][0]) if necessary_fields['links'] else 0
    features['label'] = label

    return features


def extract_features_from_folder(folder_path):
    mail_files = get_files(folder_path)
    feature_list = []

    for mail_file in mail_files:
        mail_content = extract_msg(folder_path, mail_file)
        if mail_content:
            features = overall_feature_extraction(folder_path, mail_content, mail_file)
            if features:
                feature_list.append(features)

    if len(feature_list) == 0:
        raise ValueError("No valid labeled emails found in the folder. Ensure that emails are labeled with 'spam' or 'ham'.")
    
    dfnew = pd.DataFrame(feature_list)
    return dfnew

# Boolean: if HTML is present or not
# Boolean: if HTML is present or not
def body_html(body_content):
    if body_content is None:
        return False
    body_html = bool(BeautifulSoup(body_content, "html.parser").find())
    return body_html


# Boolean: if HTML has <form> or not
# Boolean: if HTML has <form> or not
def body_forms(body_content):
    if body_content is None:
        return False
    body_forms = bool(BeautifulSoup(body_content, "html.parser").find("form"))
    return body_forms


# Integer: number of words in the body
def body_noWords(body_content):
    body_noWords = len(body_content.split())
    return body_noWords

# Integer: number of characters in the body
def body_noCharacters(body_content):
    body_noCharacters = count_characters(body_content)
    return body_noCharacters

# Integer: number of distinct words in the body
def body_noDistinctWords(body_content):
    body_noDistinctWords = len(Counter(body_content.split()))
    return body_noDistinctWords

# Float: richness of the text (body)
def body_richness(body_noWords, body_noCharacters):
    try:
        body_richness = float(body_noWords)/body_noCharacters
    except:
        body_richness = 0
    return body_richness

# Integer: number of function words in the body
def body_noFunctionWords(body_content):
    body_noFunctionWords = 0
    wordlist = re.sub("[^A-Za-z]", " ", body_content.strip()).lower().split()
    function_words = ["account", "access", "bank", "credit", "click", "identity", "inconvenience", "information", "limited", 
                      "log", "minutes", "password", "recently", "risk", "social", "security", "service", "suspended"]
    for word in function_words:
        body_noFunctionWords += wordlist.count(word)
    return body_noFunctionWords

# Boolean: if body has the word 'suspension' or not
def body_suspension(body_content):
    body_suspension = "suspension" in body_content.lower()
    return body_suspension

# Boolean: if body has the phrase 'verify your account' or not
def body_verifyYourAccount(body_content):
    phrase = "verifyyouraccount"
    content = re.sub(r"[^A-Za-z]", "", body_content.strip()).lower()
    body_verifyYourAccount = phrase in content
    return body_verifyYourAccount
  
def extract_subj_attributes(subj_content):
    if subj_content is None:
        return {
            'subj_reply': False,
            'subj_forward': False,
            'subj_noWords': 0,
            'subj_noCharacters': 0,
            'subj_richness': 0,
            'subj_verify': False,
            'subj_debit': False,
            'subj_bank': False
        }

    subj_attributes = {}
    subj_attributes['subj_reply'] = subj_reply(subj_content)
    subj_attributes['subj_forward'] = subj_forward(subj_content)
    subj_attributes['subj_noWords'] = len(subj_content.split())
    subj_attributes['subj_noCharacters'] = count_characters(subj_content)
    subj_attributes['subj_richness'] = subj_richness(subj_attributes['subj_noWords'], subj_attributes['subj_noCharacters'])
    subj_attributes['subj_verify'] = "verify" in subj_content.lower()
    subj_attributes['subj_debit'] = "debit" in subj_content.lower()
    subj_attributes['subj_bank'] = "bank" in subj_content.lower()

    return subj_attributes

'''
Functions to extract subject line based attributes
'''

# Boolean: Check if the email is a reply to any previous mail
def subj_reply(subj_content):
    if subj_content is None:
        return False
    return subj_content.lower().startswith("re:")


# Boolean: Check if the email is a forward from another mail
def subj_forward(subj_content):
    if subj_content is None:
        return False
    return subj_content.lower().startswith("fwd:")


# Integer: number of words in the subject
def subj_noWords(subj_content):
    subj_noWords = len(subj_content.split())
    return subj_noWords

# Integer: number of characters in the subject
def subj_noCharacters(subj_content):
    subj_noCharacters = count_characters(subj_content)
    return subj_noCharacters

# Float: richness of the text (subject)
def subj_richness(subj_noWords, subj_noCharacters):
    try:
        subj_richness = float(subj_noWords)/subj_noCharacters
    except:
        subj_richness = 0
    return subj_richness

# Boolean: if subject has the word 'verify' or not
def subj_verify(subj_content):
    subj_verify = "verify" in subj_content.lower()
    return subj_verify

# Boolean: if subject has the word 'debit' or not
def subj_debit(subj_content):
    subj_debit = "debit" in subj_content.lower()
    return subj_debit

# Boolean: if subject has the word 'bank' or not
def subj_bank(subj_content):
    subj_bank = "bank" in subj_content.lower()
    return subj_bank

def extract_body_attributes(body_content):
    if body_content is None:
        return {
            'body_noWords': 0,
            'body_noCharacters': 0,
            'body_richness': 0,
            'body_html': False,
            'body_forms': False,
            'body_noDistinctWords': 0,
            'body_noFunctionWords': 0,
            'body_suspension': False,
            'body_verifyYourAccount': False
        }

    return {
        'body_noWords': len(body_content.split()),
        'body_noCharacters': len(body_content),
        'body_richness': len(set(body_content.split())) / (len(body_content.split()) if len(body_content.split()) > 0 else 1),
        'body_html': body_html(body_content),
        'body_forms': body_forms(body_content),
        'body_noDistinctWords': len(set(body_content.split())),
        'body_noFunctionWords': body_noFunctionWords(body_content),
        'body_suspension': body_suspension(body_content),
        'body_verifyYourAccount': body_verifyYourAccount(body_content)
    }

'''
Functions to extract sender address based attributes
'''

# Integer: number of words in sender address
def send_noWords(send_address):
    # Check if the send_address is None
    if send_address is None:
        return 0  # Return 0 if there is no sender address
    return len(send_address.split())  # Split and count words if send_address exists

def send_noCharacters(send_address):
    # Check if the send_address is None
    if send_address is None:
        return 0  # Return 0 if there is no sender address
    return count_characters(send_address)  # Count characters if send_address exists


def get_email_domain(email_address):
    if email_address is None:
        return None  # Return None if the email address is not provided

    domain = re.search(r"@[\w.]+", email_address)
    if domain is None:
        return None
    return domain.group()[1:]  # Return the domain without '@'

# Boolean: check if sender and reply-to domains are different
def send_diffSenderReplyTo(send_address, replyTo_address):
    send_domain = get_email_domain(send_address)
    replyTo_domain = get_email_domain(replyTo_address)
    
    # If either domain is None, return False
    if send_domain is None or replyTo_domain is None:
        return False
    
    return send_domain != replyTo_domain


def get_url_domain(url):
    domain = None
    if url:
        parsed_uri = urlparse(url)
        domain = '{uri.netloc}'.format(uri=parsed_uri)
        if domain.startswith("www."):
            return domain[4:]  # Remove 'www.' prefix if present
    return domain

# Boolean: check if sender's and email's modal domain are different
def send_nonModalSenderDomain(send_address, modal_url):
    send_domain = get_email_domain(send_address)
    modal_domain = get_url_domain(modal_url)  # Now using the correctly defined function
    
    send_nonModalSenderDomain = False
    if modal_url:
        send_nonModalSenderDomain = (send_domain != modal_domain)
    return send_nonModalSenderDomain

def extract_send_attributes(send_address, replyTo_address, modal_url):
    send_attributes = {}
    
    send_attributes['send_noWords'] = send_noWords(send_address)
    send_attributes['send_noCharacters'] = send_noCharacters(send_address)
    send_attributes['send_diffSenderReplyTo'] = send_diffSenderReplyTo(send_address, replyTo_address)
    send_attributes['send_nonModalSenderDomain'] = send_nonModalSenderDomain(send_address, modal_url)
    
    return send_attributes
'''
Functions to extract URL based attributes
'''

# Boolean: if use of IP addresses rather than domain name
def url_ipAddress(links_list):
    url_ipAddress = False
    for link in links_list:
        link_address = get_url_domain(link)
        if ":" in str(link_address):
            link_address = link_address[:link_address.index(":")]
        try:
            IP(link_address)
            url_ipAddress = True
            break
        except:
            continue
    return url_ipAddress

# Integer: number of links in an email that contain IP addresses 
def url_noIpAddresses(links_list):
    url_noIpAddresses = 0
    for link in links_list:
        link_address = get_url_domain(link)
        if ":" in str(link_address):
            link_address = link_address[:link_address.index(":")]
        try:
            IP(link_address)
            url_noIpAddresses = url_noIpAddresses + 1
            break
        except:
            continue
    return url_noIpAddresses

# Boolean: if '@' symbol is present in any URL
def url_atSymbol(links_list):
    url_atSymbol = False
    for link in links_list:
        if u'@' in str(link):
            url_atSymbol = True
            break
    return url_atSymbol

# Integer: number of links in the email body
def url_noLinks(links_list):
    url_noLinks = len(links_list)
    return url_noLinks

# Integer: number of external links in email body
def url_noExtLinks(body_content):
    url_noExtLinks = len(extract_urls(body_content))
    return url_noExtLinks

# Integer: number of internal links in email body
def url_noIntLinks(links_list, body_content):
    url_noIntLinks = url_noLinks(links_list) - url_noExtLinks(body_content)
    return url_noIntLinks

# Integer: number of image links in email body
def url_noImgLinks(body_content):
    # Ensure body_content is a string, even if None
    if body_content is None:
        body_content = ""
    
    soup = BeautifulSoup(body_content, features="lxml")
    image_links = soup.findAll('img')
    return len(image_links)

# Integer: number of URL domains in email body
def url_noDomains(body_content, send_address, replyTo_address):
    domains = set()
    all_urls = extract_urls(body_content)
    for url in all_urls:
        domain = get_url_domain(url)
        domains.add(domain)
    
    domains.add(get_email_domain(send_address))
    domains.add(get_email_domain(replyTo_address))
    return len(domains)

# Integer: number of periods in the link with highest number of periods
def url_maxNoPeriods(links_list):
    max_periods = 0
    for link in links_list:
        num_periods = str(link).count('.')
        if max_periods < num_periods:
            max_periods = num_periods
    return max_periods

# Boolean: check if link text contains click, here, login or update terms
def url_linkText(body_content):
    # Ensure body_content is a string, even if None
    if body_content is None:
        body_content = ""
    
    linkText_words = ['click', 'here', 'login', 'update']
    soup = BeautifulSoup(body_content, features="lxml")
    
    for link in soup.findAll('a'):
        if link.contents:
            contents = list(re.sub(r'([^\s\w]|_)+', '', str(link.contents[0])).lower().split())
            extra_contents = set(contents).difference(set(linkText_words))
            if len(extra_contents) < len(contents):
                return True
    return False

    
# Binary: if 'here' links don't map to modal domain
def url_nonModalHereLinks(body_content, modal_url):
    # Ensure body_content is a string, even if it's None
    if body_content is None:
        return False
    
    modal_domain = get_url_domain(modal_url) if modal_url != "None" else None
    
    soup = BeautifulSoup(body_content, features="lxml")
    for link in soup.findAll('a'):
        if link.contents and isinstance(link.contents[0], str) and "here" in link.contents[0].lower():
            link_ref = link.get('href')
            if link_ref and get_url_domain(link_ref) != modal_domain:
                return True
    return False

# Boolean: if URL accesses ports other than 80
def url_ports(links_list):
    url_ports = False
    for link in links_list:
        link_address = get_url_domain(link)
        if ":" in str(link_address):
            port = link_address[link_address.index(":"):][1:]
            if str(port) != str(80):
                url_ports = True
                break
    return url_ports
    
# Integer: number of links with port information
def url_noPorts(links_list):
    url_noPorts = 0
    for link in links_list:
        link_address = get_url_domain(link)
        if ":" in str(link_address):
            url_noPorts = url_noPorts + 1
    return url_noPorts

def extract_url_attributes(links_list, body_content, send_address, replyTo_address, modal_url):
    # Ensure links_list is a list, even if None
    if links_list is None:
        links_list = []
    
    url_attributes = {}

    url_attributes['url_ipAddress'] = url_ipAddress(links_list)
    url_attributes['url_noIpAddresses'] = url_noIpAddresses(links_list)
    url_attributes['url_atSymbol'] = url_atSymbol(links_list)
    url_attributes['url_noLinks'] = url_noLinks(links_list)
    url_attributes['url_noExtLinks'] = url_noExtLinks(body_content)
    url_attributes['url_noIntLinks'] = url_noIntLinks(links_list, body_content)
    url_attributes['url_noImgLinks'] = url_noImgLinks(body_content)
    url_attributes['url_noDomains'] = url_noDomains(body_content, send_address, replyTo_address)
    url_attributes['url_maxNoPeriods'] = url_maxNoPeriods(links_list)
    url_attributes['url_linkText'] = url_linkText(body_content)
    url_attributes['url_nonModalHereLinks'] = url_nonModalHereLinks(body_content, modal_url)
    url_attributes['url_ports'] = url_ports(links_list)
    url_attributes['url_noPorts'] = url_noPorts(links_list)
    
    return url_attributes

'''
Functions to extract script based attributes
'''

# Boolean: if scripts are present in the email body
def script_scripts(body_content):
    # Check if body_content is None or empty before processing
    if body_content is None:
        return False

    # Process body_content with BeautifulSoup if it's valid
    script_scripts = bool(BeautifulSoup(body_content, "html.parser").find("script"))
    return script_scripts


# Boolean: if script present is Javascript
def script_javaScript(body_content):
    # Check if body_content is None or empty before processing
    if body_content is None:
        return False

    # Process body_content with BeautifulSoup if it's valid
    soup = BeautifulSoup(body_content, features="lxml")
    script_javaScript = False
    for script in soup.findAll('script'):
        if script.get('type') == "text/javascript":
            script_javaScript = True
            break
    return script_javaScript


# Boolean: check if script overrides the status bar in the email client
def script_statusChange(body_content):
    # Check if body_content is None or empty before processing
    if body_content is None:
        return False

    soup = BeautifulSoup(body_content, features="lxml")
    script_statusChange = False
    for script in soup.findAll('script'):
        script_text = script.string
        if script_text and "window.status" in script_text:
            script_statusChange = True
            break
    return script_statusChange


# Boolean: check if email contains pop-up window code
# Boolean: check if email contains pop-up window code
def script_popups(body_content):
    # Check if body_content is None or empty before processing
    if body_content is None:
        return False

    soup = BeautifulSoup(body_content, features="lxml")
    script_popups = False
    for script in soup.findAll('script'):
        script_text = script.string
        if script_text and ("window.open" in script_text or "window.create" in script_text):
            script_popups = True
            break
    return script_popups


# Integer: number of on-click events
def script_noOnClickEvents(body_content):
    # Check if body_content is None or empty before processing
    if body_content is None:
        return True

    soup = BeautifulSoup(body_content, features="lxml")
    script_noOnClickEvents = True
    codes = soup.findAll('button', {"onclick": True})
    if len(codes) > 0:
        script_noOnClickEvents = False
    return script_noOnClickEvents


# Boolean: if Javascript comes from outside the modal domain
def script_nonModalJsLoads(body_content, modal_url):
    # Check if body_content is None or empty before processing
    if body_content is None:
        return False

    soup = BeautifulSoup(body_content, features="lxml")
    script_nonModalJsLoads = False
    modal_domain = get_url_domain(modal_url)
    for script in soup.findAll('script'):
        src = script.get('src')
        if src:
            src_domain = get_url_domain(src)
            if src_domain != modal_domain:
                script_nonModalJsLoads = True
                break
    return script_nonModalJsLoads

  
def extract_script_attributes(body_content, modal_url):
    script_attributes = {}
    
    script_attributes['script_scripts'] = script_scripts(body_content)
    script_attributes['script_javaScript'] = script_javaScript(body_content)
    script_attributes['script_statusChange'] = script_statusChange(body_content)
    script_attributes['script_popups'] = script_popups(body_content)  # This is where it calls script_popups
    script_attributes['script_noOnClickEvents'] = script_noOnClickEvents(body_content)
    script_attributes['script_nonModalJsLoads'] = script_nonModalJsLoads(body_content, modal_url)
    
    return script_attributes

#test_path = "C:/Users/FENNY/Desktop/BE-Final/SPAM-ASSA/dataset/demo/"
mail_files = get_files(test_path)
#print len(mail_files)
#print mail_files[0]
mail0_necessary_fields = extract_necessary_fields(test_path, mail_files[0])
#pprint.pprint(mail0_necessary_fields, width = 1)
'''
Overall feature extraction (40 features)
'''

# Function to extract all the 40 features at once
def overall_feature_extraction(folder_path, mail_content, mail_file):
    # Correctly pass the mail_content (Message object) into extract_necessary_fields
    necessary_fields = extract_necessary_fields(folder_path, mail_file)

    # Determine the label based on the filename
    if "spam" in mail_file.lower():
        label = "spam"
    elif "ham" in mail_file.lower():
        label = "ham"
    else:
        print(f"Skipping non-email or unlabeled file: {mail_file}")
        return None 

    # Extract features from different parts of the email
    body_attributes = extract_body_attributes(necessary_fields.get('body'))
    subj_attributes = extract_subj_attributes(necessary_fields.get('subj'))
    send_attributes = extract_send_attributes(
        necessary_fields.get('send'),
        necessary_fields.get('replyTo'),
        necessary_fields.get('modalURL', None)  # Handle missing modalURL
    )
    url_attributes = extract_url_attributes(
        necessary_fields.get('links'),
        necessary_fields.get('body'),
        necessary_fields.get('send'),
        necessary_fields.get('replyTo'),
        necessary_fields.get('modalURL', None)  # Handle missing modalURL
    )
    script_attributes = extract_script_attributes(necessary_fields.get('body'), necessary_fields.get('modalURL', None))

    # Combine all features into one dictionary
    features = {}
    features.update(body_attributes)
    features.update(subj_attributes)
    features.update(send_attributes)
    features.update(url_attributes)
    features.update(script_attributes)
    features['label'] = label  # Assign the label
    
    return features

# Verify that everything till here is correct
mail_files = get_files(test_path)
#print mail_files[0]
#features = overall_feature_extraction(test_path, "?", mail_files[0])
#print len(features)
#pprint.pprint(features, width = 1)
'''
Extract features of all mails in a path
'''
# Extract features of all files in a path
def extract_all_features_in_path(folder_path, label):
    features_list = []
    mail_files = get_files(folder_path)
    for mail in mail_files:
        mail_content = extract_msg(folder_path, mail)  # Get the email content (Message object)
        if mail_content:  # If the email was parsed correctly
            features = overall_feature_extraction(folder_path, mail_content, mail)  # Pass both content and file name
            if features:
                features_list.append(features)
    return features_list

# Create or append all the features for all the files to a 'csv' file
def create_features_csv(features_list, filename):
    with open(filename, 'wb') as output_file:
        headers = sorted([key for key, value in features_list[0].items()])
        headers.append(headers.pop(headers.index('label')))
        
        csv_data = [headers]

        for element in features_list:
            csv_data.append([element[header] for header in headers])

        writer = csv.writer(output_file)
        writer.writerows(csv_data)
    print("create_features_csv: success")


# Verify that everything till here is correct
features_list = extract_all_features_in_path(test_path, "?")


# Function to load or train the SVM model
import joblib
from sklearn.svm import SVC
import pandas as pd

# Function to load or train the SVM model
def load_or_train_model(model_path, model_class, X_train, y_train, **model_params):
    try:
        # Attempt to load the model if it exists
        model = joblib.load(model_path)
        print(f"Existing model loaded successfully from {model_path}")
    except Exception as e:
        # If loading fails, train a new model
        print(f"Error loading existing model: {e}")
        print("Training a new model...")

        # Train the model
        model = model_class(**model_params)
        model.fit(X_train, y_train)

        # Save the trained model
        joblib.dump(model, model_path)
        print(f"New model trained and saved to {model_path}")

    return model

# Main script execution
import joblib
from colorama import Fore, Style, init
from collections import Counter
from imblearn.over_sampling import SMOTE
from imblearn.combine import SMOTETomek
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import RandomizedSearchCV, cross_val_score
from scipy.stats import uniform

# Initialize colorama for colorful terminal output
init()

# Define suspicious words
suspicious_words = ['free', 'win', 'urgent', 'click here', 'money', 'limited', 'risk', 'account']

# Main script logic
'''
Main script logic and feature extraction with error handling
'''

if __name__ == "__main__":
    # Input folder path from the user
    folder_path = input(Fore.BLUE + "Enter path of folder where mail is present: ").strip()

    # Extract features from emails
    dfnew = extract_features_from_folder(folder_path)

    # Check if dfnew has been successfully created
    if dfnew is None or dfnew.empty:
        raise ValueError("No emails found or dfnew is empty.")

    # Print the columns to verify what has been extracted
    print("Columns in dfnew:", dfnew.columns)

    # Check and handle if 'body' or 'links' columns are missing
    if 'body' not in dfnew.columns or 'links' not in dfnew.columns:
        print("Warning: 'body' or 'links' column is missing from the dataset.")
    else:
        print(f"Unique labels in the dataset: {dfnew['label'].value_counts()}")

    # Apply suspicious word count and domain extraction only if 'body' and 'links' columns exist
    if 'body' in dfnew.columns:
        dfnew['suspicious_word_count'] = dfnew['body'].apply(
            lambda x: suspicious_word_count(x, suspicious_words) if isinstance(x, str) else 0
        )
    else:
        dfnew['suspicious_word_count'] = 0  # Default value if 'body' is missing

    # Handle 'links' column safely and extract domains if it exists
    if 'links' in dfnew.columns:
        dfnew['url_domains'] = dfnew['links'].apply(
            lambda links: [extract_domain_from_url(link) for link in links] if isinstance(links, list) else []
        )
        dfnew['unique_domain_count'] = dfnew['url_domains'].apply(lambda x: len(set(x)))
    else:
        dfnew['url_domains'] = [[]] * len(dfnew)  # Default to an empty list if 'links' is missing
        dfnew['unique_domain_count'] = 0  # Default to 0 unique domains

    # Display the new features added
    print("New features added to the dataset:")
    print(dfnew[['suspicious_word_count', 'url_domains', 'unique_domain_count']].head())

    # Print additional columns only if they exist
    if 'body' in dfnew.columns and 'links' in dfnew.columns:
        print(dfnew[['body', 'suspicious_word_count', 'links', 'url_domains', 'unique_domain_count']])
    else:
        print("Warning: 'body' or 'links' column is missing from the dataset.")

    # Define the columns that will be used for training
    training_feature_columns = [
        'body_noWords', 'body_noCharacters', 'body_richness', 'url_noLinks', 'url_noImgLinks',
        'url_maxNoPeriods', 'body_noFunctionWords', 'subj_verify', 'send_diffSenderReplyTo',
        'script_statusChange', 'url_length', 'suspicious_characters', 'suspicious_word_count', 
        'unique_domain_count'
    ]

    # Filter available features for training
    available_features = [col for col in training_feature_columns if col in dfnew.columns]
    if not available_features:
        raise ValueError("None of the training features are available in the dataset.")

    # Prepare the training data
    X_train = dfnew[available_features]
    y_train = dfnew['label']

    # Step 1: Apply SMOTE for oversampling the minority class
    smote = SMOTE(random_state=42, k_neighbors=2)
    X_res, y_res = smote.fit_resample(X_train, y_train)
    print(f"Resampled dataset shape using SMOTE: {Counter(y_res)}")

    # Step 2: Combine SMOTE with SMOTETomek for better balance in classes
    smt = SMOTETomek(random_state=42, smote=SMOTE(k_neighbors=2))
    X_res_combined, y_res_combined = smt.fit_resample(X_train, y_train)
    print(f"Resampled dataset shape using SMOTETomek: {Counter(y_res_combined)}")

    # Step 3: Train the SVM model with custom class weights to prioritize ham class
    class_weights = {'ham': 2, 'spam': 1}  # Custom class weights
    svm_model = SVC(kernel='linear', C=0.1, gamma=1, class_weight=class_weights)
    svm_model.fit(X_res_combined, y_res_combined)

    # Step 4: Make predictions on the training data (X_train)
    predictions = svm_model.predict(X_train)
    print(f"Overall Accuracy with class weight adjustment: {accuracy_score(y_train, predictions) * 100:.2f}%")
    
    # Add the classification report with zero_division set to 1
    print(classification_report(y_train, predictions, zero_division=1))
    
    print(confusion_matrix(y_train, predictions))

    # Step 5: Perform Hyperparameter Tuning using Randomized Search
    param_distributions = {
        'C': uniform(0.1, 10),     # Continuous range for C
        'gamma': uniform(0.01, 1), # Continuous range for gamma
        'kernel': ['linear', 'rbf'],  # Linear and RBF kernels
    }

    random_search = RandomizedSearchCV(SVC(), param_distributions, n_iter=50, cv=3, verbose=2, random_state=42, n_jobs=-1)
    random_search.fit(X_res_combined, y_res_combined)
    print(f"Best Parameters from Randomized Search: {random_search.best_params_}")

    random_predictions = random_search.predict(X_train)
    print(f"Final Accuracy after tuning: {accuracy_score(y_train, random_predictions) * 100:.2f}%")
    print(classification_report(y_train, random_predictions, zero_division=1))  # Add this for tuned model
    print(confusion_matrix(y_train, random_predictions))

    # Step 6: Perform Cross-Validation on the best model
    cv_scores = cross_val_score(random_search.best_estimator_, X_res_combined, y_res_combined, cv=5)
    print(f"Cross-Validation Accuracy: {cv_scores.mean() * 100:.2f}%")

    # Save the trained model
    joblib.dump(random_search.best_estimator_, 'SVM_best_model.pkl')

    # Display phishing or not phishing for each email
    y_pred = predictions  # Model predictions
    y_true = y_train  # Actual labels (true values)

    # Iterate through each email prediction and display the result
    for i, prediction in enumerate(y_pred):
        result = f"{Fore.RED}Phishing{Style.RESET_ALL}" if prediction == "spam" else f"{Fore.GREEN}Not Phishing{Style.RESET_ALL}"
        print(f"Email {i + 1} is {result}!")

    # Calculate ham and spam accuracy from the confusion matrix
    confusion_matrix_values = confusion_matrix(y_true, y_pred)
    ham_accuracy = (confusion_matrix_values[0][0] / sum(confusion_matrix_values[0])) * 100 if sum(confusion_matrix_values[0]) > 0 else 0
    spam_accuracy = (confusion_matrix_values[1][1] / sum(confusion_matrix_values[1])) * 100 if sum(confusion_matrix_values[1]) > 0 else 0

    # Print the ham and spam accuracy
    print(f"\n{Fore.GREEN}Ham Accuracy: {ham_accuracy:.2f}%{Style.RESET_ALL}")
    print(f"{Fore.RED}Spam Accuracy: {spam_accuracy:.2f}%{Style.RESET_ALL}")
