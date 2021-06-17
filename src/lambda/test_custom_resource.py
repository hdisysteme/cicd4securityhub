from botocore.exceptions import ClientError
import os
import json
import pytest
from unittest.mock import MagicMock
from pathlib import Path
from botocore.stub import Stubber
import botocore.session
from collections import namedtuple


@pytest.fixture(scope="function")
def mock_env(monkeypatch):
    """Mock AWS Lambda environment for moto.

    Params:
        monkeypatch: patch object
    """
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "my-function-name")
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    monkeypatch.setenv("ACCOUNT_ID", "123456789012")


@pytest.fixture(scope="function")
def aws_credentials():
    """Mock AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


@pytest.fixture(scope="function")
def iam(aws_credentials):
    """Mock iam boto3 resource client.

    Params:
        aws_credentials: mocked aws credentials
    """
    yield botocore.session.get_session().create_client("iam")


@pytest.fixture(scope="function")
def s3(aws_credentials):
    """Mock s3 boto3 client.

    Params:
        aws_credentials: mocked aws credentials
    """
    yield botocore.session.get_session().create_client("s3")


@pytest.fixture(scope="function")
def securityhub(aws_credentials):
    """Mock s3 boto3 client.

    Params:
        aws_credentials: mocked aws credentials
    """
    yield botocore.session.get_session().create_client("securityhub")


@pytest.fixture(scope="function")
def ec2(aws_credentials):
    """Mock ec2 boto3 client.

    Params:
        aws_credentials: mocked aws credentials
    """
    yield botocore.session.get_session().create_client("ec2")


def return_event(file_name):
    """Return a Lambda event object."""
    with Path(__file__).parent.joinpath(file_name).open() as json_file:
        test_event = json.load(json_file)
    return test_event


def return_context():
    """Create a Lambda context object."""
    data = '{"log_stream_name": "demo-logstream"}'
    context = json.loads(
        data, object_hook=lambda d: namedtuple("X", d.keys())(*d.values())
    )
    return context


class TestCreateActionTarget:
    """Run tests for CloudFormation custom resource create_action_target."""

    test_event = return_event(file_name="events/create_action_target_event.json")
    context = return_context()

    def test_create_action_target(
        self, mock_env, securityhub, event=test_event["Create"],
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        properties = event["ResourceProperties"]

        response = {"ActionTargetArn": "fake-arn"}
        expected_params = {
            "Name": properties["Name"],
            "Description": properties["Description"],
            "Id": properties["Id"],
        }

        # When
        stubber.add_response("create_action_target", response, expected_params)
        with stubber:
            service_response = securityhub.create_action_target(
                Name=properties["Name"],
                Description=properties["Description"],
                Id=properties["Id"],
            )

        # Then
        assert service_response == response

    def test_send_success(self, event=test_event["Create"], context=context):
        """Test CFN-signal function.

        Args:
            event: event object
            context: context object

        Returns:
            No Return
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Give
        http = MagicMock()
        response_status = "SUCCESS"
        physical_resource_id = None
        no_echo = False
        response_url = event["ResponseURL"]
        response_body = {}
        response_data = {}
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
        headers = {"content-type": "", "content-length": str(len(json_response_body))}

        # When
        response = uat.send(
            http,
            event,
            context,
            response_status,
            response_data,
            physical_resource_id,
            no_echo=False,
        )

        # Then
        http.request.assert_called_with(
            "PUT",
            response_url,
            body=json_response_body.encode("utf-8"),
            headers=headers,
        )
        assert response is True

    def test_send_failure(self, event=test_event["Create"], context=context):
        """Test CFN-signal function.

        Args:
            event: event object
            context: context object

        Returns:
            No Return
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Give
        http = MagicMock()
        http.request.return_value = Exception
        response_data = {}
        response_status = "FAILED"
        physical_resource_id = None
        no_echo = False
        response_url = event["ResponseURL"]
        response_body = {
            "Status": response_status,
            "Reason": (
                "See the details in CloudWatch Log Stream: " + context.log_stream_name
            ),
            "PhysicalResourceId": (physical_resource_id or context.log_stream_name),
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": no_echo,
            "Data": response_data,
        }
        json_response_body = json.dumps(response_body)
        headers = {"content-type": "", "content-length": str(len(json_response_body))}

        # When
        response = uat.send(
            http,
            event,
            context,
            response_status,
            response_data,
            physical_resource_id,
            no_echo=False,
        )

        # Then
        http.request.assert_called_with(
            "PUT",
            response_url,
            body=json_response_body.encode("utf-8"),
            headers=headers,
        )
        assert response is False

    def test_create_create_action_target(
        self, mock_env, event=test_event["Create"], context=context
    ):
        """Test successful creation of custom action.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock

        # Given
        properties = event["ResourceProperties"]
        securityhub.create_action_target.return_value = {
            "ActionTargetArn": "arn:aws:securityhub:eu-central-1:012345678910:action/custom/dmzapplypatch",
        }

        # When
        uat.create_action_target(
            event, context, securityhub=securityhub, response_data={}
        )

        # Then
        securityhub.create_action_target.assert_called_with(
            Name=properties["Name"],
            Description=properties["Description"],
            Id=properties["Id"],
        )

    def test_update_create_action_target(
        self, mock_env, event=test_event["Update"], context=context
    ):
        """Test successful update of custom action.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock

        # Given
        securityhub.create_action_target.return_value = {
            "ActionTargetArn": "arn:aws:securityhub:eu-west-1:012345678910:action/custom/dmzapplypatch",
        }
        # When
        uat.create_action_target(
            event, context, securityhub=securityhub, response_data={}
        )

        # Then
        assert securityhub.delete_action_target.call_count == 1
        assert securityhub.create_action_target.call_count == 1

    def test_delete_create_action_target(
        self, mock_env, event=test_event["Delete"], context=context
    ):
        """Test successful deletion of custom action.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock

        # Given
        properties = event["ResourceProperties"]
        account_id = os.environ["ACCOUNT_ID"]
        region = os.environ["AWS_REGION"]
        action_target_arn = "arn:aws:securityhub:{}:{}:action/custom/{}".format(
            region, account_id, properties["Id"]
        )

        # When
        response = uat.create_action_target(
            event, context, securityhub=securityhub, response_data={}
        )

        # Then
        securityhub.delete_action_target.assert_called_with(
            ActionTargetArn=action_target_arn
        )
        assert response is True

    def test_uncatched_error_delete_create_action_target(
        self, mock_env, event=test_event["Delete"], context=context
    ):
        """Test bad deletion of custom action.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Given
        securityhub = MagicMock()
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.delete_action_target.side_effect = exceptions.InternalException(
            error_response={
                "Error": {
                    "Code": "InternalException",
                    "Message": "Securityhub deleted",
                }
            },
            operation_name="DeleteActionTarget",
        )

        # When
        try:
            uat.create_action_target(
                event, context, securityhub=securityhub, response_data={}
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAccessException":
                # Then
                assert True
            else:
                # Then
                assert False

    def test_catched_error_delete_create_action_target(
        self, mock_env, event=test_event["Delete"], context=context
    ):
        """Test catched bad deletion of custom action.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Given
        securityhub = MagicMock()
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.delete_action_target.side_effect = exceptions.InvalidAccessException(
            error_response={
                "Error": {
                    "Code": "InvalidAccessException",
                    "Message": "invaled access",
                }
            },
            operation_name="DeleteActionTarget",
        )

        # When
        try:
            uat.create_action_target(
                event, context, securityhub=securityhub, response_data={}
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAccessException":
                # Then
                assert True
            else:
                # Then
                assert False

    def test_error_update_create_action_target(
        self, mock_env, event=test_event["Update"], context=context
    ):
        """Test bad update of custom actions.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Given
        securityhub = MagicMock()
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.create_action_target.side_effect = exceptions.InternalException(
            error_response={
                "Error": {"Code": "InternalException", "Message": "Internal exception",}
            },
            operation_name="CreateActionTarget",
        )

        # When
        try:
            uat.create_action_target(
                event, context, securityhub=securityhub, response_data={}
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAccessException":
                # Then
                assert True
            else:
                # Then
                assert False

    def test_catched_client_error_create_create_action_target(
        self, mock_env, event=test_event["Create"], context=context
    ):
        """Test catched bad creation of custom actions.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Given
        securityhub = MagicMock()
        securityhub.create_action_target.return_value = {
            "ActionTargetArn": "arn:aws:securityhub:eu-central-1:107383926673:action/custom/dmzapplypatch",
        }
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.delete_action_target.side_effect = exceptions.InvalidAccessException(
            error_response={
                "Error": {
                    "Code": "InvalidAccessException",
                    "Message": "Securityhub already deleted",
                }
            },
            operation_name="DeleteActionTarget",
        )

        # When
        try:
            uat.create_action_target(
                event, context, securityhub=securityhub, response_data={}
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAccessException":
                # Then
                assert True
            else:
                # Then
                assert False

    def test_catched_other_error_create_create_action_target(
        self, mock_env, event=test_event["Create"], context=context
    ):
        """Test catched bad creation of custom actions.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.create_action_target.create_action_target as uat

        # Given
        securityhub = MagicMock()
        securityhub.create_action_target.return_value = {
            "ActionTargetArn": "arn:aws:securityhub:eu-central-1:107383926673:action/custom/dmzapplypatch",
        }
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.delete_action_target.side_effect = exceptions.LimitExceededException(
            error_response={
                "Error": {
                    "Code": "LimitExceededException",
                    "Message": "LimitExceededException",
                }
            },
            operation_name="DeleteActionTarget",
        )

        # When
        try:
            uat.create_action_target(
                event, context, securityhub=securityhub, response_data={}
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAccessException":
                # Then
                assert True
            else:
                # Then
                assert False


class TestEnableProwler:
    """Run tests for CloudFormation custom resource enable_prowler."""

    test_event = return_event(file_name="events/enable_prowler.json")
    context = return_context()

    def test_enable_import_findings_for_product(
        self, securityhub, event=test_event["Create"],
    ):
        """Test API call enable_import_findings_for_product.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        prowler_arn = event["ResourceProperties"]["IntegrationARN"]

        response = {"ProductSubscriptionArn": prowler_arn}
        expected_params = {
            "ProductArn": prowler_arn,
        }

        # When
        stubber.add_response(
            "enable_import_findings_for_product", response, expected_params
        )
        with stubber:
            service_response = securityhub.enable_import_findings_for_product(
                ProductArn=prowler_arn,
            )

        # Then
        assert service_response == response

    def test_successful_enable_integration(
        self, event=test_event["Create"], context=context
    ):
        """Test successful enablement of Prowler.

        Params:
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.enable_prowler as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock

        # Given
        prowler_arn = event["ResourceProperties"]["IntegrationARN"]

        # When
        response = uat.enable_integration(
            event, context, securityhub=securityhub, response_data={}
        )

        # Then
        securityhub.enable_import_findings_for_product.assert_called_with(
            ProductArn=prowler_arn,
        )
        assert response is True

    def test_nothing_to_do(self, event=test_event["Delete"], context=context):
        """Test skipp enablement of Prowler.

        Params:
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.enable_prowler as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock

        # Given
        prowler_arn = event["ResourceProperties"]["IntegrationARN"]

        # When
        response = uat.enable_integration(
            event, context, securityhub=securityhub, response_data={}
        )

        # Then
        securityhub.enable_import_findings_for_product.assert_called_with(
            ProductArn=prowler_arn,
        )
        assert response is True

    def test_key_error(self, event=test_event["KeyError"], context=context):
        """Test skipp enablement of Prowler.

        Params:
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.enable_prowler as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock

        # Given

        # When
        response = uat.enable_integration(
            event, context, securityhub=securityhub, response_data={}
        )

        # Then
        assert response is False

    def test_error_enable_integration(
        self, event=test_event["Create"], context=context
    ):
        """Test error enablement of Prowler.

        Params:
            event: Lambda event object
            context: Lambda context object
        """
        import custom_resource.enable_prowler as uat  # Import here, so moto has the chance to mock all client initiations

        # Given
        securityhub = MagicMock()
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.enable_import_findings_for_product.side_effect = exceptions.InvalidAccessException(
            error_response={
                "Error": {"Code": "InvalidAccessException", "Message": "Key not found",}
            },
            operation_name="EnableImportFindingsForProduct",
        )

        # When
        response = uat.enable_integration(
            event, context, securityhub=securityhub, response_data={}
        )
        assert response is False

    def test_send_success(self, event=test_event["Create"], context=context):
        """Test CFN-signal function.

        Args:
            event: event object
            context: context object

        Returns:
            No Return
        """
        import custom_resource.enable_prowler as uat

        # Give
        http = MagicMock()
        response_data = {}
        response_status = "SUCCESS"
        physical_resource_id = None
        no_echo = False
        response_url = event["ResponseURL"]
        response_body = {
            "Status": response_status,
            "Reason": (
                "See the details in CloudWatch Log Stream: " + context.log_stream_name
            ),
            "PhysicalResourceId": (physical_resource_id or context.log_stream_name),
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": no_echo,
            "Data": response_data,
        }
        json_response_body = json.dumps(response_body)
        headers = {"content-type": "", "content-length": str(len(json_response_body))}

        # When
        response = uat.send(
            http,
            event,
            context,
            response_status,
            response_data,
            physical_resource_id,
            no_echo=False,
        )

        # Then
        http.request.assert_called_with(
            "PUT",
            response_url,
            body=json_response_body.encode("utf-8"),
            headers=headers,
        )
        assert response is True

    def test_send_failure(self, event=test_event["Create"], context=context):
        """Test CFN-signal function.

        Args:
            event: event object
            context: context object

        Returns:
            No Return
        """
        import custom_resource.enable_prowler as uat

        # Give
        http = MagicMock()
        http.request.return_value = Exception
        response_data = {}
        response_status = "FAILED"
        physical_resource_id = None
        no_echo = False
        response_url = event["ResponseURL"]
        response_body = {
            "Status": response_status,
            "Reason": (
                "See the details in CloudWatch Log Stream: " + context.log_stream_name
            ),
            "PhysicalResourceId": (physical_resource_id or context.log_stream_name),
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": no_echo,
            "Data": response_data,
        }
        json_response_body = json.dumps(response_body)
        headers = {"content-type": "", "content-length": str(len(json_response_body))}

        # When
        response = uat.send(
            http,
            event,
            context,
            response_status,
            response_data,
            physical_resource_id,
            no_echo=False,
        )

        # Then
        http.request.assert_called_with(
            "PUT",
            response_url,
            body=json_response_body.encode("utf-8"),
            headers=headers,
        )
        assert response is False
