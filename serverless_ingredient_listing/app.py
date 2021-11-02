import json
import boto3
from pymongo import MongoClient
import os
import jwt

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
    token_receive = event['headers']['Authorization']
    secret = os.environ["JWT_SECRET_KEY"]

    if token_receive != 'anonymous':
        try:
            payload = jwt.decode(token_receive, secret, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return {
                "statusCode": 401,
                'headers': {
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'OPTIONS,GET'
                }
            }

        if payload is None:
            return {
                "statusCode": 401,
                'headers': {
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'OPTIONS,GET'
                }
            }

        user_id = payload["user_id"]
        user = db.user.find_one({"_id": user_id})
    else:
        user = {'id': ''}
        print("access_token is empty")

    irdnt = list(db.recipe_ingredient.distinct("IRDNT_NM"))
    recipe = list(db.recipe_basic.distinct("RECIPE_NM_KO"))

    return {
        "statusCode": 200,
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,GET'
        },
        "body": json.dumps({
            "result": "success",
            "recipe_ingredient": irdnt,
            "recipe_name_kor": recipe
        }),
    }