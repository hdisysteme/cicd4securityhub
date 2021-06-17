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


def enable_integration(
    event, context, securityhub=securityhub, response_data=response_data
):
    """Enable Prowler integration in SecurityHub.

    Params:
        client: securityhub boto3 client
        response_data: empty dict
        event: Lambda event object
        context: Lambda context object
    Returns:
        CFN Signal
    """
    logger.info("Enabling Prowler Integration")
    try:
        prowler_arn = event["ResourceProperties"]["IntegrationARN"]
    except KeyError:
        logger.error("Error: Missing Key")
        response_data["Message"] = "Failure"
        send(
            http=http,
            event=event,
            context=context,
            response_status="FAILED",
            response_data=response_data,
        )
        return False
    if event["RequestType"] == "Create":
        try:
            securityhub.enable_import_findings_for_product(ProductArn=prowler_arn,)
        except ClientError as e:
            logger.exception(e)
            response_data["Message"] = "Failure"
            send(
                http=http,
                event=event,
                context=context,
                response_status="FAILED",
                response_data=response_data,
            )
            return False
        logger.info("Enable Prowler Integration")
        response_data["Message"] = "Success"
        send(
            http=http,
            event=event,
            context=context,
            response_status="SUCCESS",
            response_data=response_data,
        )
        return True
    else:
        logger.info("Nothing to do")
        response_data["Message"] = "Success"
        send(
            http=http,
            event=event,
            context=context,
            response_status="SUCCESS",
            response_data=response_data,
        )
        return True
