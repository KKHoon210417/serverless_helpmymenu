import json
import boto3
from pymongo import MongoClient
import hashlib
import os

def get_secret():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name="ap-northeast-2"
    )
    get_secret_value_response = client.get_secret_value(
        SecretId='pymongo-secret-01'
    )
    token = get_secret_value_response['SecretString']
    return eval(token)

# MongoDB
secrets = get_secret()

client = MongoClient("mongodb://{0}:{1}@{2}".format(secrets['user'],secrets['password'],secrets['host']))
db = client.dbrecipe

def lambda_handler(event, context):
    try:
        if event['httpMethod'] == 'OPTIONS':
            body = json.dumps({
                "message": "success",
            })
        else:
            data = json.loads(event['body'])
            print(data)
            username_receive = data['username_give']
            email_receive = data['email_give']
            email_exists = bool(db.users.find_one({"EMAIL": email_receive}))

            if email_exists:
                return {
                    "body": json.dumps({
                        "message": "fail:email_exists",
                    })
                }

            password_receive = data['password_give']
            password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
            doc = {
                "USERNAME": username_receive,  # 사용자 이름 / 프로필에 표시되는 이름
                "EMAIL": email_receive,  # 이메일
                "PASSWORD": password_hash,  # 비밀번호
                "PROFILE_PIC": "",  # 프로필 사진 파일 이름
                "PROFILE_PIC_REAL": f"{os.environ['BUCKET_ENDPOINT']}/profile_pics/profile_placeholder.png",
                # 프로필 사진 기본 이미지
                "PROFILE_INFO": ""  # 프로필 한 마디
            }
            print(doc)
            print(os.environ['BUCKET_ENDPOINT'])
            db.users.insert_one(doc)

            body = json.dumps({
                "message": "success",
            })

        return {
            "statusCode": 200,
            # Cross Origin처리
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
            "body": body,
        }
    except Exception as e:
        print(e)
        return {
            "statusCode": 500,
            # Cross Origin처리
            'headers': {
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'OPTIONS,POST'
            },
            "body": json.dumps({
                "message": "fail",
            }),
        }