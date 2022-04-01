import boto3
import json
import logging
import os
import urllib3

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
    
    data = event['detail']
    
    logger.info("Event        : " + str(event))
    
    # 정보
    event_id = data['eventID']
    
    # 주체
    user_name = data['userIdentity']['userName']
    source_ip = data['sourceIPAddress']
    acount = data['userIdentity']['accountId']

    # 이벤트 내역
    event_time = data['eventTime']
    event_name = data['eventName']
    aws_region = data['awsRegion']
    groupId = (data['requestParameters']['groupId'])
    port = (data['requestParameters']['ipPermissions']['items'][0]['toPort'])
    protocol = (data['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
    ipv4 = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
    ipv6 = (data['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])
    
    ct_url = f"https://{aws_region}.console.aws.amazon.com/cloudtrail/home?region={aws_region}#/events/{event_id}"
    
    try:
        description = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
    except KeyError as e:
        description = "None"
    
    event_source = data['eventSource']
    
    logger.info("HOOK URL     : " + HOOK_URL)
    
    slack_message = {
            "@type": "MessageCard",
            "themeColor": "FF0000",
            "summary": "SG Rule 생성 탐지",
            "sections": [
                {
                    "activityTitle": "AWS Security Group Notice",
                    "activitySubtitle": "SG Rule 생성 탐지",
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
                            "value": user_name
                        },
                        {
                            "name": "SG ID",
                            "value": groupId
                        },  
                        {
                            "name": "Protocol",
                            "value": protocol
                        },
                        {
                            "name": "Port",
                            "value": port
                        },
                        {
                            "name": "Source IP",
                            "value": ipv4
                        },
                        {
                            "name": "Description",
                            "value": description
                        }
                    ],
                }
            ]
    }
    
    logger.info("Slack Message        : " + str(slack_message))
    send_message(slack_message)
