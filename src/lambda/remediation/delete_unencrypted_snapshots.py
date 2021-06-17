import boto3
import os
import logging
from botocore.exceptions import ClientError

ec2 = boto3.client("ec2")
securityhub = boto3.client("securityhub")

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)


def lambda_handler(event, context, ec2=ec2, securityhub=securityhub):
    """Remediate findings related to prowler740.

    Params:
        securityhub: securityhub boto3 client
        ec2: ec2 boto3 client
        event: Lambda event object
        context: Lambda context object
    """
    non_compliant_snapshotss = event["detail"]["findings"]
    lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
    account_id = os.environ["ACCOUNT_ID"]
    for non_compliant_snapshot in non_compliant_snapshotss:
        non_compliant_snapshot_generator = non_compliant_snapshot["Id"]
        snapshot_id = non_compliant_snapshot_generator.replace(
            "prowler-7.40-{}-eu-central-1-eu-central-1_".format(account_id), ""
        )
        snapshot_id = snapshot_id.replace("_is_currently_not_encrypted_", "")
        finding_id = non_compliant_snapshot["Id"]
        product_arn = non_compliant_snapshot["ProductArn"]
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id,)
        except ClientError as e:
            logger.exception(e)
            raise e
        try:
            securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn},],
                Note={
                    "Text": "Deleted unencrypted snapshot " + snapshot_id,
                    "UpdatedBy": lambda_name,
                },
                Workflow={"Status": "RESOLVED"},
            )
            logger.info("Deleted unencrypted snapshot " + snapshot_id)
        except ClientError as e:
            logger.exception(e)
            raise e
