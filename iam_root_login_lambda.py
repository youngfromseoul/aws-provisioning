import boto3
import json
import logging
import os
import time
import urllib3

from datetime import datetime
from datetime import timedelta
from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

http = urllib3.PoolManager()

HOOK_URL = os.environ['HOOK_URL']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def send_message(message):
    
    data = json.dumps(message, default=str).encode('utf-8')

    res = http.request(
        method='POST',
        url=HOOK_URL,
        body=data
    )
    print(res.data, res.status)

def lambda_handler(event, context):
    
    logger.info("Event: " + str(event))
    data = event['detail']
    
    # time
    event_time = data['eventTime'][:19]
    kst_event_time = datetime.strptime(event_time, '%Y-%m-%dT%H:%M:%S') - timedelta(hours=-9)
    
    # sourceIPAddress
    sourceIPAddress = data['sourceIPAddress']
    
    # Acount
    acount = data['userIdentity']['accountId']
    
    logger.info("HOOK URL     : " + HOOK_URL)

    # 이벤트 타입 구분
    event_type = data['eventName']
    
    if event_type == "SwitchRole":
        switchStatusCheck = data['responseElements']['SwitchRole']
        switchUserName = data['additionalEventData']['SwitchFrom']
        switch_message = {
            "@type": "MessageCard",
            "themeColor": "0076D7",
            "summary": "AWS Console Login",
            "sections": [
                {
                    "activityTitle": "AWS Console Login Notice",
                    "activitySubtitle": "AWS Switch Role",
                    "facts": [
                        {
                            "name": "Time",
                            "value": kst_event_time
                        },
                        {
                            "name": "Acount ID",
                            "value": accountname
                        },
                        {
                            "name": "SwitchFrom",
                            "value": switchUserName
                        },
                        {
                            "name": "Source IP",
                            "value": sourceIPAddress
                        },
                        {
                            "name": "Status",
                            "value": switchStatusCheck
                        }
                    ]
                }
            ]
        }
        logger.info("Slack Message        : " + str(switch_message))
        send_message(switch_message)
    else:
        loginStatusCheck = data['responseElements']['ConsoleLogin']
        usedMFA = data['additionalEventData']['MFAUsed']
        accountType = data['userIdentity']['type']
    
        # Root 인지 IAMUser 인지 구분
        if accountType == "Root":
            accountUserName = "Root"
        elif accountType == "IAMUser":
            accountUserName = data['userIdentity']['userName']
        else:
            accountUserName = " "
        
        if accountUserName == "HIDDEN_DUE_TO_SECURITY_REASONS":
            accountUserName = "User Not Found"
        
        login_message = {
            "@type": "MessageCard",
            "themeColor": "0076D7",
            "summary": "AWS Console Login",
            "sections": [
                {
                    "activityTitle": "AWS Console Login Notice",
                    "activitySubtitle": "AWS Console Login",
                    "facts": [
                        {
                            "name": "Time",
                            "value": kst_event_time
                        },
                        {
                            "name": "Acount ID",
                            "value": accountname
                        },
                        {
                            "name": "User",
                            "value": accountUserName
                        },
                        {
                            "name": "Source IP",
                            "value": sourceIPAddress
                        },
                        {
                            "name": "Status",
                            "value": loginStatusCheck
                        },  
                        {
                            "name": "MFA",
                            "value": usedMFA
                        }
                    ]
                }
            ]
        }
        logger.info("Slack Message        : " + str(login_message))
        send_message(login_message)
