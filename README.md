# aws_stealth_perm_enum
Research on the enumeration of IAM permissions without logging to CloudTrail

## tl;dr
As of 09/09/2020 there exists a vulnerability in the AWS API that allows you to enumerate some IAM permissions for a role without logging to CloudTrail. This capability is due to improper handling of the Content-Type header which is important for the AWS API. The vulnerability has been reported to the AWS Security Team and in the event that it is patched, here are all the details of said vulnerability. It currently affects the following AWS services.

* secretsmanager
* sagemaker
* route53domains
* workmail
* shield
* cur (Cost and Usage Reports)
* comprehend
* cloudhsm
* autoscaling-plans
* application-autoscaling
* datapipeline
* codepipeline
* codestar
* budgets
* sms (Server Migration Service)
* support
* kinesis
* kinesisanalytics
* macie
* forecast
* gamelift
* health
* dax (DynamoDB DB Accelerator)
* directconnect
* discovery
* textract
* translate

## Steps to Reproduce
The vulnerability only affects AWS services that use POST requests and the X-Amz-Target header (Each AWS API has different implementations. Some use GET requests, some POST to an API endpoint, etc). The majority of these services require the Content-Type header to be 'application/x-amz-json-1.1'. In the majority of instances, sending 'application/x-amz-json-1.0' will provide you with an error; typically 404 - 'UnknownOperationException' or 500 - 'InternalFailure'.

However, on the services listed above you instead will get a 403 response if you do not have permission to call the API. If the role does have permission to call the API you instead get a 404. Seemingly, because of this header none of this traffic is sent to CloudTrail, meaning you can enumerate whether or not a given role has privileges to make the API call without that reconaisance being logged.

There are some caveats that should be noted, however. Let's take Secrets Manager for example. 
