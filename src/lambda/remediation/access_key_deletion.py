import boto3
import datetime
import os
import logging
from botocore.exceptions import ClientError

iam = boto3.client("iam")
securityhub = boto3.client("securityhub")

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)


def lambda_handler(event, context, iam=iam, securityhub=securityhub):
    """Remediate findings related to cis14.

    Params:
        securityhub: securityhub boto3 client
        iam: iam boto3 resource client
        event: Lambda event object
        context: Lambda context object
    """
    non_rotated_keys = event["detail"]["findings"]
    lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    today = datetime.datetime.now(datetime.timezone.utc)
    for non_rotated_key in non_rotated_keys:
        user_name = non_rotated_key["Resources"][0]["Details"]["AwsIamUser"]["UserName"]
        finding_id = non_rotated_key["Id"]
        product_arn = non_rotated_key["ProductArn"]
        try:
            response = iam.list_access_keys(UserName=user_name,)
            access_key_id = response["AccessKeyMetadata"][0]["AccessKeyId"]
            key_age = today - response["AccessKeyMetadata"][0]["CreateDate"]
        except ClientError as e:
            logger.exception(e)
            raise e
        if key_age >= datetime.timedelta(days=90):
            try:
                iam.delete_access_key(
                    AccessKeyId=access_key_id, UserName=user_name,
                )
            except ClientError as e:
                logger.exception(e)
                raise
            try:
                securityhub.batch_update_findings(
                    FindingIdentifiers=[
                        {"Id": finding_id, "ProductArn": product_arn,},
                    ],
                    Note={"Text": "Access key deleted!", "UpdatedBy": lambda_name,},
                    Workflow={"Status": "RESOLVED"},
                )
            except ClientError as e:
                logger.exception(e)
                raise
