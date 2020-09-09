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

There are some caveats that should be noted, however. Let's take Secrets Manager for example. Within Secrets Manager there are two API calls which automatically set their value to resource:\*, those are secretsmanager:ListSecrets and secretsmanager:GetRandomPassword. 

Now, if you use the vulnerability without your current role having permissions to call the secretsmanager:ListSecrets action you will get a 403 response as shown below.

![403 response](https://frichetten.com/images/misc/aws_stealth_enum/403_res_1.png)

However, if you modify the IAM policy to include privileges for these two actions, it will default to resource:\*, and give you the following text.
 
![The actions you chose support all resources](https://frichetten.com/images/misc/aws_stealth_enum/resources.png)

And when rendered via JSON you get the following.

![Showing permissions.](https://frichetten.com/images/misc/aws_stealth_enum/iam_perms_1.png)

After allowing those permissions to take effect, if you run the same script again, you will receive a 404 response as shown below.

![404 response](https://frichetten.com/images/misc/aws_stealth_enum/404_res_1.png)

Depending on the 403 or 404 response you will know whether or not the role has permission to call the secretsmanager:ListSecrets action. There are many AWS API call's which only work with resource:\*, these are just two.

For more specific actions let's look at secretsmanager:GetSecretValue.

If the role does not have this permission, and we make the request we will get a 403 response (regardless of whether or not the secret id is real or not).

![403 get secret](https://frichetten.com/images/misc/aws_stealth_enum/403_res_2.png)

If you do provide the role the IAM permissions to get a specific secret, and then query that specific secret or one that does not exist, you will still get a 403 response. Because of this, if the IAM policy is locked to a specific ARN, you will not be able to enumerate the permission using this method.

![403 get secret](https://frichetten.com/images/misc/aws_stealth_enum/403_res_2.png)

However, if you instead modify the IAM policy to allow resource:\* as shown below...

![IAM Resources](https://frichetten.com/images/misc/aws_stealth_enum/iam_perms_2.png)

You will get a 404 response.

![404 response](https://frichetten.com/images/misc/aws_stealth_enum/404_res_2.png)

For whatever reason, when parsing the API query given the Content-Type: x-amz-json-1.0 header, the API service will return different response codes allowing us to determine our IAM permissions without logging to CloudTrail. From an attackers perspective, if you get a 404 response, you know the IAM action and whether or not the resource is set to \*.

## Proof of Concept
If you would like to test this for yourself, create a role with the example policy (in this repo) and then create the temporary credentials to assume the role (don't forget to set them in your environment variables). From there, run the proof of concept script, and it will determine what permissions you do and do not have access to. Wait 15-30 minutes, and then confirm that those API calls were not tracked in CloudTrail.

![Output](https://frichetten.com/images/misc/aws_stealth_enum/output.png)

![Not in CloudTrail](https://frichetten.com/images/misc/aws_stealth_enum/no_cloudtrail.png)
