import boto3
import json
import logging
import os
import time

from datetime import datetime
from datetime import timedelta
from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

HOOK_URL = os.environ['HOOK_URL']
SLACK_CHANNEL = os.environ['TeamsChannel']


logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
        
    # KST 시간 변환
    state_login_time = data['eventTime'][:19]
    kst_login_time = datetime.strptime(state_login_time, '%Y-%m-%dT%H:%M:%S') - timedelta(hours=-9) #KST 시간 변환
    
    # Slack Message Title
    title = "[%s]%s AWS Console Login" %(accountType, accountUserName)
    
    # sourceIPAddress
    sourceIPAddress = data['sourceIPAddress']
    
    # MFA 사용 유무
    usedMFA = data['additionalEventData']['MFAUsed']
    
    # 접속 성공 유무
    loginStatusCheck = data['responseElements']['ConsoleLogin']
    
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': "*%s*\n>>>*접속시간*\n%s\n*접속 IPAddress*\n%s\n*Console Login 결과*\n%s\n*MFA 사용유무*\n%s" % (title, kst_login_time, sourceIPAddress, loginStatusCheck, usedMFA)
    }

    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)