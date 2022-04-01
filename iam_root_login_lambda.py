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
    
    data = json.dumps(message).encode('utf-8')

    res = http.request(
        method='POST',
        url=HOOK_URL,
        body=data
    )
    print(res.data, res.status)

def lambda_handler(event, context):
    
    logger.info("Event: " + str(event))
    data = event['detail']
    
    accountType = data['userIdentity']['type']
    
    # Root 인지 IAMUser 인지 구분
    if accountType == "Root":
        accountUserName = "Root"
    elif accountType == "IAMUser":
        accountUserName = data['userIdentity']['userName']
    else:
        accountUserName = " "
        
    # 시간
    event_time = data['eventTime']
    
    # sourceIPAddress
    sourceIPAddress = data['sourceIPAddress']
    
    # MFA 사용 유무
    usedMFA = data['additionalEventData']['MFAUsed']
    
    # Acount
    acount = data['userIdentity']['accountId']
    
    # 접속 성공 유무
    loginStatusCheck = data['responseElements']['ConsoleLogin']
    
    
    logger.info("HOOK URL     : " + HOOK_URL)
    
    slack_message = {
            "@type": "MessageCard",
            "themeColor": "0076D7",
            "summary": "AWS Console Login",
            "sections": [
                {
                    "activityTitle": "AWS Console Login Notice",
                    "activitySubtitle": "AWS Console Login",
                    "facts": [
                        {
                            "name": "Time(UTC)",
                            "value": event_time
                        },
                        {
                            "name": "Acount ID",
                            "value": acount
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
        
    logger.info("Slack Message        : " + str(slack_message))
    
    send_message(slack_message)
