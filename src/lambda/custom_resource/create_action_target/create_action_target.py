import json
import boto3
import os
import logging
import urllib3
from botocore.exceptions import ClientError

http = urllib3.PoolManager()

log_level = os.environ.get("LOG_LEVEL", "INFO")
logging.root.setLevel(logging.getLevelName(log_level))
logger = logging.getLogger(__name__)

securityhub = boto3.client("securityhub")
response_data = {}


def send(
    http,
    event,
    context,
    response_status,
    response_data,
    physical_resource_id=None,
    no_echo=False,
):
    """Build CustomResource.

    Args:
        event: event object
        context: context object
        status: string
        data: message
        body: response

    Returns:
        No Return
    """
    response_url = event["ResponseURL"]
    logger.info(response_url)
    response_body = {}
    response_body["Status"] = response_status
    response_body["Reason"] = (
        "See the details in CloudWatch Log Stream: " + context.log_stream_name
    )
    response_body["PhysicalResourceId"] = (
        physical_resource_id or context.log_stream_name
    )
    response_body["StackId"] = event["StackId"]
    response_body["RequestId"] = event["RequestId"]
    response_body["LogicalResourceId"] = event["LogicalResourceId"]
    response_body["NoEcho"] = no_echo
    response_body["Data"] = response_data

    json_response_body = json.dumps(response_body)
    logger.info("Response body:\n" + json_response_body)
    headers = {"content-type": "", "content-length": str(len(json_response_body))}

    try:
        response = http.request(
            "PUT",
            response_url,
            body=json_response_body.encode("utf-8"),
            headers=headers,
        )
        logger.info("Status code: " + response.reason)
        return True
    except Exception as e:
        logger.exception("send(..) failed executing requests.put(..): " + str(e))
        return False


def create_action_target(
    event, context, securityhub=securityhub, response_data=response_data
):
    """Create, delete and update custom actions.

    Params:
        mock_env: mocked Lambda environment
        event: Lambda event object
        context: Lambda context object
        response_data: Custom resource signal
    """
    try:
        properties = event["ResourceProperties"]
        account_id = os.environ["ACCOUNT_ID"]
        region = os.environ["AWS_REGION"]
        if event["RequestType"] == "Create":
            response = securityhub.create_action_target(
                Name=properties["Name"],
                Description=properties["Description"],
                Id=properties["Id"],
            )
            response_data["Arn"] = response["ActionTargetArn"]
        elif event["RequestType"] == "Update":
            securityhub.delete_action_target(
                ActionTargetArn="arn:aws:securityhub:{}:{}:action/custom/{}".format(
                    region, account_id, properties["Id"]
                )
            )
            response = securityhub.create_action_target(
                Name=properties["Name"],
                Description=properties["Description"],
                Id=properties["Id"],
            )
            response_data["Arn"] = response["ActionTargetArn"]
        elif event["RequestType"] == "Delete":
            try:
                securityhub.delete_action_target(
                    ActionTargetArn="arn:aws:securityhub:{}:{}:action/custom/{}".format(
                        region, account_id, properties["Id"]
                    )
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "InvalidAccessException":
                    logger.error(
                        "Securityhub already deleted, deleting Custom Resource {}".format(
                            e
                        )
                    )
                    send(
                        http=http,
                        event=event,
                        context=context,
                        response_status="SUCCESS",
                        response_data=response_data,
                    )
                    return True
                else:
                    logger.error("Error deleting Custom Action {}".format(e))
                    send(
                        http=http,
                        event=event,
                        context=context,
                        response_status="FAILED",
                        response_data=response_data,
                    )
                    return False
        send(
            http=http,
            event=event,
            context=context,
            response_status="SUCCESS",
            response_data=response_data,
        )
        return True
    except Exception as e:
        logger.info(e)
        send(
            http=http,
            event=event,
            context=context,
            response_status="FAILED",
            response_data=response_data,
        )
        return False
