import boto3
import os
import logging
from botocore.exceptions import ClientError

iam = boto3.client("iam")
securityhub = boto3.client("securityhub")

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)


def lambda_handler(event, context, iam=iam, securityhub=securityhub):
    """Remediate findings related to cis15 and cis11.

    Params:
        event: Lambda event object
        context: Lambda context object
        iam: iam boto3 client
        securityhub: securityhub boto3 client
    Returns:
        No returns
    """
    finding_id = event["detail"]["findings"][0]["Id"]
    product_arn = event["detail"]["findings"][0]["ProductArn"]
    lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    try:
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
            HardExpiry=True,
        )
        logger.info("IAM Password Policy Updated")
    except ClientError as e:
        logger.exception(e)
        raise e
    try:
        securityhub.batch_update_findings(
            FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn},],
            Note={
                "Text": "Changed non compliant password policy",
                "UpdatedBy": lambda_name,
            },
            Workflow={"Status": "RESOLVED"},
        )
    except ClientError as e:
        logger.exception(e)
        raise e
