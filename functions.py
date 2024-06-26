# functions.py
import httpx
import re
import private
import asyncio
import backoff
import requests
import base64
import asyncio
#import aiohttp
import json
import os
from email.utils import parseaddr
from email.header import decode_header
from email.parser import BytesParser
from email.policy import default as default_policy


# Function to load phishing keywords from a file
def load_phishing_keywords(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        line = file.readline().strip()
        keywords = line.split(',')
        print("cargado fichero")
    return keywords

# Get the full path to the whitelist.txt file
base_dir = os.path.dirname(os.path.abspath(__file__))
whitelist_path = os.path.join(base_dir, 'whitelist.txt')

# Load phishing keywords
phishing_keywords = load_phishing_keywords(whitelist_path)

# Function to check if the subject contains phishing keywords
def contains_phishing_keywords(subject, keywords):
    subject_lower = subject.lower()
    for word in keywords:
        if word in subject_lower:
            return True
    return False

# Function to process an .eml file
async def process_eml_file(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=default_policy).parse(f)

    sender = msg['From']

    """domain_consistency = check_domain_consistency(sender)
    phishing_status = "Name doesn't match with domain" if not domain_consistency else "Remitente verificado"""

    recipient = msg['To']
    subject = msg['Subject']
    reply = msg.get('Reply-To', 'No reply-to address') 
    print("checkpoint1")

    # Check if Reply-To matches From
    reply_to_check = "OK" if reply == 'No reply-to address' or reply == sender else "Reply-To doesn't match From"
    # Validate authentication results (DKIM, SPF, DMARC, ARC)
    authentication_checks = verify_email_headers(msg)

        
        
    # Extract and validate URLs
    urls = extract_urls_from_email(msg)
    urls_count = len(urls)
    # Limit the number of URLs to analyze to 12
    limited_urls = urls[:12] 

    # Asynchronously check the safety of each URL, only up to the first 12
    check_urls = [is_url_safe(url, len(limited_urls)) for url in limited_urls]
    results = await asyncio.gather(*check_urls)
    
    unsafe_urls = [url for url, is_safe in zip(urls, results) if not is_safe]

    # Extract IPs from the email
    ips = extract_ips_from_headers(msg)
    abuse_reports = await check_ips_with_abuseipdb(ips)

    # Check for phishing keywords in the subject
    phishing_in_subject = contains_phishing_keywords(subject, phishing_keywords)

    # Building the user message
    message = f"Sender Details:\n-----------------------\n"
    message += f"- From: {sender}\n- To: {recipient}\n- Subject: {subject}\n- Reply-To: {reply} ({reply_to_check})\n\n"
    message += "Authentication Results:\n-----------------------\n"
    for key, value in authentication_checks.items():
        message += f"- {key}: {value}\n"
    

    message += "\nURLs Found in the Email:\n------------------------\n"
    if urls:
        non_clickable_urls = make_urls_non_clickable(urls)
        for index, url in enumerate(non_clickable_urls, 1):
            message += f"{index}. {url}\n"
    else:
        message += "No URLs found in the email.\n"

    if unsafe_urls:
        message += "\nWarnings:\n---------\n- The following URLs have been detected as unsafe and may pose security risks:\n"
        non_clickable_unsafe_urls = make_urls_non_clickable(unsafe_urls)
        for index, url in enumerate(non_clickable_unsafe_urls, 1):
            message += f"  {index}. {url}\n"
    else:
        message += "\n - All URLs found appear to be safe.\n"
    
    if abuse_reports:
        message += "\nIP Address Reports:\n------------------------\n"
        for report in abuse_reports:
            message += f"IP Address: {report['ipAddress']}, Abuse Score: {report['abuseConfidenceScore']}, Last Reported: {report['lastReportedAt']}\n"
    else:
        message += "\n - No abusive IP addresses found.\n"
    
     # Conclusions section
    message += "\nConclusions:\n------------------------\n"
    phishing_detected = False
    possible_phishing = False

    # Check for malicious URLs
    if unsafe_urls:
        message += "- Phishing detected: One or more URLs are malicious.\n"
        phishing_detected = True

    # Check for Reply-To mismatch and authentication failures
    if reply_to_check != "OK":
        message += "- Possible phishing: Reply-To doesn't match From.\n"
        possible_phishing = True
    
    failed_auth_checks = sum(1 for key, value in authentication_checks.items() if value == "Failed")
    if failed_auth_checks >= 2:
        message += "- Possible phishing: At least 2 authentication checks failed.\n"
        possible_phishing = True

    # Check for abuse score
    high_abuse_ips = [report for report in abuse_reports if report['abuseConfidenceScore'] > 10]
    if high_abuse_ips:
        message += "- Possible phishing: One or more IP addresses have a high abuse score (> 50).\n"
        possible_phishing = True

    # Check for phishing keywords in the subject
    if phishing_in_subject:
        message += "- Possible phishing: The subject contains words indicating urgency or potential phishing.\n"
        possible_phishing = True

    if not phishing_detected and not possible_phishing:
        message += "- No signs of phishing detected.\n"
    
    # Recommendations section
    message += "\nRecomendations:\n------------------------\n"
    message += "Always check that the sender's name matches the email or makes sense if not don't trust the email."


    return message

# Function to make URLs non-clickable
def make_urls_non_clickable(urls):
    """ Transforma URLs en versiones no clicables """
    non_clickable_urls = []
    for url in urls:
        # Replace 'http' with 'hxxp' and '.' with '[.]'
        modified_url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        modified_url = re.sub(r"\.", "[.]", modified_url)
        non_clickable_urls.append(modified_url)
    return non_clickable_urls

# Function to verify email headers
def verify_email_headers(msg):
    authentication_results = msg.get('Authentication-Results', '')
    print("\nprueba" + authentication_results+ "\n")
    dmarc_status = 'dmarc=pass' in authentication_results
    dkim_status = 'dkim=pass' in authentication_results
    spf_status = 'spf=pass' in authentication_results
    arc_status = 'arc=pass' in authentication_results

    checks = {
        'DMARC Status': 'Passed' if dmarc_status else 'Failed',
        'DKIM Status': 'Passed' if dkim_status else 'Failed',
        'SPF Status': 'Passed' if spf_status else 'Failed',
        'ARC Status': 'Passed' if arc_status else 'Failed'
    }
    
    return checks

# Function to extract unique and valid IPv4 addresses from email headers
def extract_ips_from_headers(msg):
    """
    Extract unique and valid IPv4 addresses from the email headers.
    """
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    header_ips = set()
    for header, value in msg.items():
        # Exclude date and time patterns to avoid false positives
        cleaned_value = re.sub(r'\b\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2}\b', '', value)
        header_ips.update(re.findall(ipv4_pattern, cleaned_value))

    # Filter out invalid IPs (those with octets > 255)
    valid_ips = [ip for ip in header_ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
    
    print("Extracted IPs from headers:", valid_ips)
    return valid_ips


# Function to extract URLs from the email content
def extract_urls_from_email(msg):
    body = msg.get_body(preferencelist=('plain', 'html')).get_content()
    # Regex for URLs
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    print(urls)
    return urls

# Function to check the safety of a URL using VirusTotal API
async def is_url_safe(url, urls_count):
    if urls_count <= 4:
        api_key = private.api_key_virustotal1
    elif urls_count <= 8:
        api_key = private.api_key_virustotal2
    else:
        api_key = private.api_key_virustotal3
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    # Submit the URL for analysis
    submit_response = await submit_url_for_analysis(url, headers)
    if not submit_response:
        return False
    
    # Get the analysis ID and wait for it to complete
    analysis_id = submit_response["data"]["id"]
    # Wait for 15 seconds before requesting the result
    await asyncio.sleep(15)
    print("check")
    analysis_result = await get_analysis_result(analysis_id, headers)
    
    # Interpret the analysis results
    if not analysis_result:
        return False
    
    stats = analysis_result["data"]["attributes"]["stats"]
    print("-------------------------------------------------------------------------")
    print(stats)
    print("-------------------------------------------------------------------------")
    malicious_count = stats.get("malicious", 0) #+ stats.get("suspicious", 0)
    
    # Consider the URL as unsafe if at least one engine reports it as malicious
    is_safe = malicious_count == 0
    return is_safe

# Function to submit a URL for analysis to VirusTotal
async def submit_url_for_analysis(url, headers):
    submit_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(submit_url, headers=headers, data=payload)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error submitting URL for analysis: {response.text}")
            return None

# Function to get the analysis result from VirusTotal
async def get_analysis_result(analysis_id, headers):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(analysis_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error getting analysis result: {response.text}")
            return None

# Function to check IP addresses with AbuseIPDB
async def check_ips_with_abuseipdb(ips):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': private.api_key_abuseip
    }
    abuse_reports = []
    async with httpx.AsyncClient() as client:
        for ip in ips:
            params = {'ipAddress': ip, 'maxAgeInDays':'90'}
            print(ip)
            response = await client.get(url, headers=headers, params=params)
            print(response)
            if response.status_code == 200:
                data = response.json()
                print(f"Data received for IP {ip}: {data}")
                if data['data']['abuseConfidenceScore'] >= 10:
                    abuse_reports.append({
                        'ipAddress': data['data']['ipAddress'],
                        'abuseConfidenceScore': data['data']['abuseConfidenceScore'],
                        'lastReportedAt': data['data']['lastReportedAt']
                    })
            else:
                print(f"Error querying AbuseIPDB for IP {ip}: {response.text}")
    print(f"repoerte de abuse_report: {abuse_reports}")
    return abuse_reports

# Function to analyze a URL using URLScan
async def analyze_url(url, api_key):
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "private"}
    async with httpx.AsyncClient() as client:
        response = await client.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        print(response)
        if response.status_code == 200:
            return response.json()
        else:
            return response.json()
        

# Function to analyze a message with GPT
async def analyze_message_with_gpt(message, api_key_gpt):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key_gpt}",
        "Content-Type": "application/json",
    }
    
    bot_description = (
        "You are now PhishFighterBot. You provide concise and direct answers suitable for instant messaging platforms like Telegram. "
        "This GPT strives to be clear and efficient in its communication, respecting the quick nature of exchanges in messaging apps, "
        "without sacrificing the quality of the information provided. Respond based on the language of the following message.\n\nMessage: "
    )

    data = {
        "model": "gpt-4-0125-preview",
        "messages": [
            {"role": "system", "content": bot_description},
            {"role": "user", "content": message}
        ],
    }
    
    @backoff.on_exception(backoff.expo, httpx.ReadTimeout, max_time=30)
    async def send_request():
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, headers=headers, json=data)
            return response

    try:
        response = await send_request()
        if response.status_code == 200:
            response_data = response.json()
            print(response_data)
            if "choices" in response_data and len(response_data["choices"]) > 0:
                gpt_response = response_data["choices"][0]["message"]["content"]
                return gpt_response
        else:
            print("Error in GPT request:", response.text)
    except httpx.ReadTimeout:
        print("The request has exceeded the maximum allowed timeout.")
    return None
    
# Function to safely send messages in chunks if they exceed the maximum message length
async def safe_send_message(context, chat_id, text):
    MAX_MESSAGE_LENGTH = 4096
    messages = [text[i:i + MAX_MESSAGE_LENGTH] for i in range(0, len(text), MAX_MESSAGE_LENGTH)]
    for message in messages:
        await context.bot.send_message(chat_id=chat_id, text=message)