import boto3
import os
import logging
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)


def lambda_handler(event, context, s3=s3, securityhub=securityhub):
    """Remediate findings related to s34.

    Params:
        event: Lambda event object
        s3: boto3 s3 client
        securityhub: boto3 securityhub client
        context: Lambda context object
    """
    lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    non_cmpliant_s3s = event["detail"]["findings"]
    for s3_bucket in non_cmpliant_s3s:
        s3_bucket_arn = s3_bucket["Resources"][0]["Id"]
        s3_bucket_name = s3_bucket_arn.split("arn:aws:s3:::")[1]
        try:
            s3.put_bucket_encryption(
                Bucket=s3_bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                            }
                        },
                    ]
                },
            )
        except ClientError as e:
            logger.exception(e)
            raise
        try:
            securityhub.batch_update_findings(
                FindingIdentifiers=[
                    {"Id": s3_bucket["Id"], "ProductArn": s3_bucket["ProductArn"]},
                ],
                Note={
                    "Text": "Put SSE with KMS for " + s3_bucket_name,
                    "UpdatedBy": lambda_name,
                },
                Workflow={"Status": "RESOLVED"},
            )

            logger.info("Put SSE with KMS for " + s3_bucket_name)
        except ClientError as e:
            logger.exception(e)
            raise
