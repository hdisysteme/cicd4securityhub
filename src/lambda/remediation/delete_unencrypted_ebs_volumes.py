import boto3
import os
from botocore.exceptions import ClientError
import logging

ec2 = boto3.client("ec2")
securityhub = boto3.client("securityhub")

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)


def lambda_handler(event, context, ec2=ec2, securityhub=securityhub):
    """Remediate findings related to prowler729.

    Params:
        securityhub: securityhub boto3 client
        ec2: ec2 boto3 client
        event: Lambda event object
        context: Lambda context object
    """
    non_compliant_ebss = event["detail"]["findings"]
    lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    account_id = os.environ["ACCOUNT_ID"]
    for non_compliant_ebs in non_compliant_ebss:
        non_compliant_ebs_generator = non_compliant_ebs["Id"]
        ebs_id = non_compliant_ebs_generator.replace(
            "prowler-7.29-{}-eu-central-1-eu-central-1_".format(account_id), ""
        )
        ebs_id = ebs_id.replace("_is_not_encrypted_", "")
        finding_id = non_compliant_ebs["Id"]
        product_arn = non_compliant_ebs["ProductArn"]
        try:
            ec2.delete_volume(VolumeId=ebs_id, DryRun=False)
        except ClientError as e:
            if e.response["Error"]["Code"] == "VolumeInUse":
                message = e.response["Error"]["Message"]
                logger.exception(message)
                instance_id = message.split("attached to ")[1]
                try:
                    ec2.terminate_instances(InstanceIds=[instance_id])
                except ClientError as e:
                    logger.exception(e)
                    raise e
        try:
            securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn},],
                Note={
                    "Text": "Deleted unencrypted volume and/or terminated instance "
                    + ebs_id,
                    "UpdatedBy": lambda_name,
                },
                Workflow={"Status": "RESOLVED"},
            )
            logger.info("Deleted unencrypted volume and or deleted instance")
        except ClientError as e:
            logger.exception(e)
            raise e
