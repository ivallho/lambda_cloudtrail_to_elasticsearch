# CloudTrail_To_Elasticsearch

Lmabda function to receive S3 notifications for PUT object to index CloudTrail logs on an Elasticsearch Service cluster.


## Index formatting
The function creates a daily index and maps key string fields as not_analyzed to aggregate on awsRegion, arn...

* _index: cloudtrail-yyyy-mm-dd
* _type: cloudtrail
* _id: eventId

## Setup

You need to add the following dependencies to the [package](http://docs.aws.amazon.com/lambda/latest/dg/lambda-python-how-to-create-deployment-package.html) uploaded to lambda:
* [elasticsearch](https://github.com/elastic/elasticsearch-py)
* [requests_aws4auth](https://github.com/sam-washington/requests-aws4auth)

Replace "host" and "region" with the endpoint and region of your Elasticsearch Service cluster

Make sure the lambda executor IAM role has permissions to access your ESS cluster and S3 bucket:

```javascript
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GrantGetObject",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::your_cloudtrail_bucket/*"
            ]
        },	
	{
	    "Sid": "GrantESAccess",
            "Effect": "Allow",
            "Action": [
                "es:*"
            ],
            "Resource": "arn:aws:es:*:*:*"
        }
    ]
}

```
Once you have the Lambda function created, enable S3 Event Notifications for PUT Object on the prefix where CloudTrail logs are delivered and subscribe the created Lambda function.