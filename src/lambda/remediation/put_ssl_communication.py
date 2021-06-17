import boto3
import os
import json
from botocore.exceptions import ClientError
import logging

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)


def lambda_handler(event, context, s3=s3, securityhub=securityhub):
    """Test successfull remediation for s35.

    Params:
        event: Lambda event object
        context: Lambda context object
        s3: s3 boto3 client
        securityhub: securityhub boto3 client
    Returns:
        No returns
    """
    lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    non_compliant_s3s = event["detail"]["findings"]
    statement_list = []
    for s3_bucket in non_compliant_s3s:
        s3_bucket_arn = s3_bucket["Resources"][0]["Id"]
        s3_bucket_name = s3_bucket_arn.split("arn:aws:s3:::")[1]
        try:
            response = s3.get_bucket_policy(Bucket=s3_bucket_name)
            uncompliant_policy = response["Policy"]
            json_uncompliant_policy = json.loads(uncompliant_policy)
            for i in json_uncompliant_policy["Statement"]:
                statement_list.append(i)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                logger.info(e)
            else:
                logger.exception(e)
                raise
        try:
            ssl_only_statement = {
                "Sid": "AllowSSLRequestsOnly",
                "Action": "s3:*",
                "Effect": "Deny",
                "Resource": [
                    "arn:aws:s3:::{}".format(s3_bucket_name),
                    "arn:aws:s3:::{}/*".format(s3_bucket_name),
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                "Principal": "*",
            }
            statement_list.append(ssl_only_statement)
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": statement_list,
            }
            bucket_policy = json.dumps(bucket_policy)
            s3.put_bucket_policy(Bucket=s3_bucket_name, Policy=bucket_policy)
        except ClientError as e:
            logger.exception(e)
            raise
        try:
            securityhub.batch_update_findings(
                FindingIdentifiers=[
                    {"Id": s3_bucket["Id"], "ProductArn": s3_bucket["ProductArn"]},
                ],
                Note={
                    "Text": "Put SSL-Communication-Only for " + s3_bucket_name,
                    "UpdatedBy": lambda_name,
                },
                Workflow={"Status": "RESOLVED"},
            )
            logger.info("Put SSL-Communication-Only for {}".format(s3_bucket_name))
        except ClientError as e:
            logger.exception(e)
            raise
