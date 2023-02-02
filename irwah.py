import requests
import sys
import json
from requests import packages

# Silence insecure request warning
requests.packages.urllib3.disable_warnings()


alert_file = open(sys.argv[1])
user = sys.argv[2].split(':')[0]
api_key = sys.argv[2].split(':')[1]
hook_url = sys.argv[3]
# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

alert_level = alert_json['rule']['level']
ruleid = alert_json['rule']['id']
description = alert_json['rule']['description']
agentid = alert_json['agent']['id']
agentname = alert_json['agent']['name']
fulllog = alert_json['full_log']

data = {
    "alert_level": alert_level,
    "rule_id": ruleid,
    "alert_description": description,
    "agent_id": agentid,
    "agent_name": agentname,
    "full_log": fulllog
}

headers = {
    "Content-Type": "application/json"
}

response = requests.post(hook_url, headers=headers, data=data, verify=False)

print(response.text)