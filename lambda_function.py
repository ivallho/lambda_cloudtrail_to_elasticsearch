#!/usr/bin/python

from __future__ import print_function

import json
import os
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers
from requests_aws4auth import AWS4Auth
from datetime import datetime 
import boto3
from StringIO import StringIO
import gzip

print('Loading function')

def lambda_handler(event, context):

    host = 'your_elasticsearchservice_endpoint'
    region = "your_elasticsearchservice_cluster_region"
    awsauth = AWS4Auth(os.environ['AWS_ACCESS_KEY_ID'], os.environ['AWS_SECRET_ACCESS_KEY'], region, 'es', session_token=os.environ['AWS_SESSION_TOKEN'])
    
    mappings={"mappings" : {
                 "cloudtrail":{
             		"properties" : {
             			"userIdentity" : {
                    			"type":"object",
                    			"properties":{
                            		"arn" : { "type" : "string", "index" : "not_analyzed" },
                            		"accountId": { "type" : "string", "index" : "not_analyzed" },
                            		"invokedBy": { "type" : "string", "index" : "not_analyzed" },
                            		"userName": { "type" : "string", "index" : "not_analyzed" }
                            	}
                        	},
                    	"eventSource": { "type" : "string", "index" : "not_analyzed" },
                    	"awsRegion": { "type" : "string", "index" : "not_analyzed" },
                    	"userAgent": { "type" : "string", "index" : "not_analyzed" }
                    	
                    	},
                    "dynamic_templates":[
                    	{"resourceIdentifiers":{
                    		"match":"*Id",
                    		"match_mapping_type":"string",
                    		"mapping":{
                    			"type":"string",
                    			"index":"not_analyzed"
                    			}
                    		}
                    	},
                    	{"resourceIdentifiersLower":{
                    		"match":"*id",
                    		"match_mapping_type":"string",
                    		"mapping":{
                    			"type":"string",
                    			"index":"not_analyzed"
                    			}
                    		}
                    	},
                    	{"resourceIdentifiersUpper":{
                    		"match":"*ID",
                    		"match_mapping_type":"string",
                    		"mapping":{
                    			"type":"string",
                    			"index":"not_analyzed"
                    			}
                    		}
                    	}
                    ]
            	}
       	}
     }

    index = 'cloudtrail-' + datetime.strftime(datetime.utcnow(),'%Y-%m-%d')

    es = Elasticsearch(
        hosts=[{'host': host, 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )
    
    if not es.indices.exists(index):
        es.indices.create(index=index,body=mappings)

    s3 = boto3.client('s3')

    bucket_name=event['Records'][0]['s3']['bucket']['name']
    key_name=event['Records'][0]['s3']['object']['key']

    if not "CloudTrail-Digest" in key_name:
        obj = s3.get_object(Bucket=bucket_name,Key=key_name)
        compressed = StringIO(obj['Body'].read())
        decompressed = gzip.GzipFile(fileobj=compressed,mode='rb')
        raw_event = json.loads(decompressed.read())

        bulk_json = []

        for record in raw_event['Records']:
            entry={"_op_type":"index","_index":index,"_type":"cloudtrail","_id":record['eventID'],"_source":record}
            bulk_json.append(entry)

        for success,info in helpers.parallel_bulk(es,bulk_json,thread_count=4):
            if not success:
                print('Failed to index document: ',info)
    else:
        print("File %s is a digest. Skipping",key_name)
