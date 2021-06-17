from botocore.exceptions import ClientError
import os
import json
import pytest
from unittest.mock import MagicMock
from pathlib import Path
from botocore.stub import Stubber
import botocore.session
import datetime
from datetime import timezone
from unittest.mock import ANY
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


class TestAccessKeyDeletion:
    """Run tests for remediation of cis14."""

    test_event = return_event(file_name="events/access_key_deletion.json")
    context = return_context()

    def test_list_access_keys(self, iam):
        """Test API call list_access_keys.

        Params:
            iam: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(iam)
        user_name = "fake-user"

        response = {
            "AccessKeyMetadata": [
                {
                    "UserName": user_name,
                    "AccessKeyId": "demo-fake-access-key-id",
                    "Status": "Active",
                    "CreateDate": datetime.datetime(2015, 1, 1),
                },
            ],
        }

        expected_params = {
            "UserName": user_name,
        }

        # When
        stubber.add_response("list_access_keys", response, expected_params)
        with stubber:
            service_response = iam.list_access_keys(UserName=user_name)

        # Then
        assert service_response == response

    def test_delete_access_key(self, iam):
        """Test API call delete_access_key.

        Params:
            iam: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(iam)
        user_name = "fake-user"
        access_key_id = "demo-fake-access-key-id"
        response = {}

        expected_params = {
            "UserName": user_name,
            "AccessKeyId": access_key_id,
        }

        # When
        stubber.add_response("delete_access_key", response, expected_params)
        with stubber:
            service_response = iam.delete_access_key(
                AccessKeyId=access_key_id, UserName=user_name,
            )

        # Then
        assert service_response == response

    def test_batch_update_findings(
        self, securityhub, event=test_event,
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        lambda_name = "fake-lambda"
        finding_id = event["detail"]["findings"][0]["Id"]
        product_arn = event["detail"]["findings"][0]["ProductArn"]
        notice = "Access key deleted!"

        response = {
            "ProcessedFindings": [{"Id": finding_id, "ProductArn": product_arn},],
            "UnprocessedFindings": [],
        }
        expected_params = {
            "FindingIdentifiers": [{"Id": finding_id, "ProductArn": product_arn,},],
            "Note": {"Text": notice, "UpdatedBy": lambda_name,},
            "Workflow": {"Status": "RESOLVED"},
        }

        # When
        stubber.add_response("batch_update_findings", response, expected_params)
        with stubber:
            service_response = securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn,},],
                Note={"Text": notice, "UpdatedBy": lambda_name,},
                Workflow={"Status": "RESOLVED"},
            )

        # Then
        assert service_response == response

    def test_successful_remediation(self, mock_env, event=test_event, context=context):
        """Test successful remediation for cis14.

        Params:
            mock_env: mocked Lambda environment
            iam: mocked iam boto3 resource client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.access_key_deletion as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock
        iam = MagicMock()

        # Given
        lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
        user_name = event["detail"]["findings"][0]["Resources"][0]["Details"][
            "AwsIamUser"
        ]["UserName"]
        notice = "Access key deleted!"
        access_key_id = "FooBar"
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "UserName": user_name,
                    "AccessKeyId": access_key_id,
                    "Status": "Active",
                    "CreateDate": datetime.datetime(2015, 1, 1, tzinfo=timezone.utc),
                },
            ],
        }

        # When
        uat.lambda_handler(event, context, iam=iam, securityhub=securityhub)

        # Then
        iam.list_access_keys.assert_called_with(UserName=user_name)
        iam.delete_access_key.assert_called_with(
            UserName=user_name, AccessKeyId=access_key_id
        )
        securityhub.batch_update_findings.assert_called_with(
            FindingIdentifiers=[
                {
                    "Id": event["detail"]["findings"][0]["Id"],
                    "ProductArn": event["detail"]["findings"][0]["ProductArn"],
                },
            ],
            Note={"Text": notice, "UpdatedBy": lambda_name},
            Workflow={"Status": "RESOLVED"},
        )

    def test_nothing_to_do(self, mock_env, event=test_event, context=context):
        """Test skipped remediation for cis14.

        Params:
            mock_env: mocked Lambda environment
            iam: mocked iam boto3 resource client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.access_key_deletion as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock
        iam = MagicMock()
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "UserName": "FooBar",
                    "AccessKeyId": "FakeID",
                    "Status": "Active",
                    "CreateDate": datetime.datetime.now(datetime.timezone.utc),
                },
            ],
        }

        # Given
        user_name = event["detail"]["findings"][0]["Resources"][0]["Details"][
            "AwsIamUser"
        ]["UserName"]

        # When
        uat.lambda_handler(event, context, iam=iam, securityhub=securityhub)

        # Then
        iam.list_access_keys.assert_called_with(UserName=user_name)
        assert iam.delete_access_key.call_count == 0
        assert securityhub.batch_update_findings.call_count == 0

    def test_client_error_list_access_keys(
        self, mock_env, event=test_event, context=context
    ):
        """Test error on remediation for cis14.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object

        Returns:
            No returns
        """
        import remediation.access_key_deletion as uat

        # Given
        iam = MagicMock()
        model = botocore.session.get_session().get_service_model("iam")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        iam.list_access_keys.side_effect = exceptions.LimitExceededException(
            error_response={
                "Error": {
                    "Code": "LimitExceededException",
                    "Message": "LimitExceededException",
                }
            },
            operation_name="ListAccessKeys",
        )

        securityhub = MagicMock()

        # When
        try:
            uat.lambda_handler(event, context, securityhub=securityhub, iam=iam)
        except ClientError as e:
            if e.response["Error"]["Code"] == "LimitExceededException":
                # Then
                assert True
            else:
                # Then
                assert False


class TestDeleteUnencryptedEBSVolumes:
    """Run tests for remediation of prowler729."""

    test_event = return_event(file_name="events/delete_unencrypted_ebs_volumes.json")
    context = return_context()
    prowler_string = "prowler-7.29-{}-eu-central-1-eu-central-1_"
    notice = "Deleted unencrypted volume and/or terminated instance "

    def test_batch_update_findings(
        self,
        mock_env,
        securityhub,
        event=test_event,
        prowler_string=prowler_string,
        notice=notice,
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        lambda_name = "fake-lambda"
        account_id = os.environ["ACCOUNT_ID"]
        finding_id = event["detail"]["findings"][0]["Id"]
        product_arn = event["detail"]["findings"][0]["ProductArn"]
        non_compliant_ebs_generator = event["detail"]["findings"][0]["Id"]
        ebs_id = non_compliant_ebs_generator.replace(
            prowler_string.format(account_id), ""
        )
        ebs_id = ebs_id.replace("_is_not_encrypted_", "")
        response = {
            "ProcessedFindings": [{"Id": finding_id, "ProductArn": product_arn},],
            "UnprocessedFindings": [],
        }
        expected_params = {
            "FindingIdentifiers": [{"Id": finding_id, "ProductArn": product_arn,},],
            "Note": {"Text": notice + ebs_id, "UpdatedBy": lambda_name,},
            "Workflow": {"Status": "RESOLVED"},
        }

        # When
        stubber.add_response("batch_update_findings", response, expected_params)
        with stubber:
            service_response = securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn,},],
                Note={
                    "Text": "Deleted unencrypted volume and/or terminated instance "
                    + ebs_id,
                    "UpdatedBy": lambda_name,
                },
                Workflow={"Status": "RESOLVED"},
            )

        # Then
        assert service_response == response

    def test_delete_volume(
        self, mock_env, ec2, event=test_event, prowler_string=prowler_string
    ):
        """Test API call delete_volume.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(ec2)
        account_id = os.environ["ACCOUNT_ID"]
        non_compliant_ebs_generator = event["detail"]["findings"][0]["Id"]
        ebs_id = non_compliant_ebs_generator.replace(
            prowler_string.format(account_id), ""
        )
        ebs_id = ebs_id.replace("_is_not_encrypted_", "")

        response = {
            "ResponseMetadata": {"Foo": "Bar",},
        }

        expected_params = {
            "VolumeId": ebs_id,
            "DryRun": False,
        }

        # When
        stubber.add_response("delete_volume", response, expected_params)
        with stubber:
            service_response = ec2.delete_volume(VolumeId=ebs_id, DryRun=False)

        # Then
        assert service_response == response

    def test_successful_remediation_ebs_only(
        self, mock_env, event=test_event, context=context, notice=notice
    ):
        """Test successful remediation for prowler729 on a unattached ebs volume.

        Params:
            mock_env: mocked Lambda environment
            ec2: mocked ec2 boto3  client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.delete_unencrypted_ebs_volumes as uat

        securityhub = MagicMock()
        ec2 = MagicMock()

        # Given
        account_id = os.environ["ACCOUNT_ID"]
        lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
        ebs_id = event["detail"]["findings"][0]["Id"].replace(
            "prowler-7.29-{}-eu-central-1-eu-central-1_".format(account_id), ""
        )
        ebs_id = ebs_id.replace("_is_not_encrypted_", "")

        # When
        uat.lambda_handler(event, context, securityhub=securityhub, ec2=ec2)

        # Then
        ec2.delete_volume.assert_called_with(VolumeId=ebs_id, DryRun=False)
        securityhub.batch_update_findings.assert_called_with(
            FindingIdentifiers=[
                {
                    "Id": event["detail"]["findings"][0]["Id"],
                    "ProductArn": event["detail"]["findings"][0]["ProductArn"],
                },
            ],
            Note={"Text": notice + ebs_id, "UpdatedBy": lambda_name,},
            Workflow={"Status": "RESOLVED"},
        )

    def test_successful_remediation_ebs_ec2(
        self, mock_env, event=test_event, context=context
    ):
        """Test successful remediation for prowler729 on a running ec2.

        Params:
            mock_env: mocked Lambda environment
            ec2: mocked ec2 boto3  client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.delete_unencrypted_ebs_volumes as uat

        securityhub = MagicMock()
        ec2 = MagicMock()

        # Given

        message = """An error occurred (VolumeInUse) when calling the DeleteVolume operation:
        Volume vol-f5e37889 is currently attached to i-66a02e5a965ecc3f0
        """

        ec2.delete_volume.side_effect = botocore.exceptions.ClientError(
            error_response={"Error": {"Code": "VolumeInUse", "Message": message,}},
            operation_name="DeleteVolume",
        )

        # When
        uat.lambda_handler(event, context, securityhub=securityhub, ec2=ec2)

        # Then
        ec2.delete_volume.assert_called_with(VolumeId=ANY, DryRun=False)
        ec2.terminate_instances.assert_called_with(InstanceIds=[ANY])
        assert securityhub.batch_update_findings.call_count == 1


class TestDeleteUnencryptedSnapshots:
    """Run tests for remediation of prowler740."""

    test_event = return_event(file_name="events/delete_unencrypted_snapshots.json")
    context = return_context()
    prowler_string = "prowler-7.40-{}-eu-central-1-eu-central-1_"
    notice = "Deleted unencrypted snapshot "

    def test_batch_update_findings(
        self,
        mock_env,
        securityhub,
        event=test_event,
        prowler_string=prowler_string,
        notice=notice,
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        lambda_name = "fake-lambda"
        account_id = os.environ["ACCOUNT_ID"]
        finding_id = event["detail"]["findings"][0]["Id"]
        product_arn = event["detail"]["findings"][0]["ProductArn"]
        non_compliant_snapshot_generator = event["detail"]["findings"][0]["Id"]
        snapshot_id = non_compliant_snapshot_generator.replace(
            prowler_string.format(account_id), ""
        )
        snapshot_id = snapshot_id.replace("_is_not_encrypted_", "")

        response = {
            "ProcessedFindings": [{"Id": finding_id, "ProductArn": product_arn},],
            "UnprocessedFindings": [],
        }
        expected_params = {
            "FindingIdentifiers": [{"Id": finding_id, "ProductArn": product_arn,},],
            "Note": {"Text": notice + snapshot_id, "UpdatedBy": lambda_name,},
            "Workflow": {"Status": "RESOLVED"},
        }

        # When
        stubber.add_response("batch_update_findings", response, expected_params)
        with stubber:
            service_response = securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn,},],
                Note={"Text": notice + snapshot_id, "UpdatedBy": lambda_name,},
                Workflow={"Status": "RESOLVED"},
            )

        # Then
        assert service_response == response

    def test_delete_snapshot(
        self, mock_env, ec2, event=test_event, prowler_string=prowler_string,
    ):
        """Test API call delete_volume.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(ec2)
        account_id = os.environ["ACCOUNT_ID"]
        non_compliant_snapshot_generator = event["detail"]["findings"][0]["Id"]
        snapshot_id = non_compliant_snapshot_generator.replace(
            prowler_string.format(account_id), ""
        )
        snapshot_id = snapshot_id.replace("_is_currently_not_encrypted_", "")

        response = {
            "ResponseMetadata": {"Foo": "Bar",},
        }

        expected_params = {
            "SnapshotId": snapshot_id,
        }

        # When
        stubber.add_response("delete_snapshot", response, expected_params)
        with stubber:
            service_response = ec2.delete_snapshot(SnapshotId=snapshot_id)

        # Then
        assert service_response == response

    def test_successful_remediation(
        self,
        mock_env,
        event=test_event,
        context=context,
        prowler_string=prowler_string,
        notice=notice,
    ):
        """Test successful remediation for prowler740 on a unattached ebs volume.

        Params:
            mock_env: mocked Lambda environment
            ec2: mocked ec2 boto3  client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.delete_unencrypted_snapshots as uat

        securityhub = (
            MagicMock()
        )  # There is no moto mock for the securityhub client, so we use "standard" pytest Mock
        ec2 = MagicMock()

        # Given
        account_id = os.environ["ACCOUNT_ID"]
        lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]

        snapshot_id = event["detail"]["findings"][0]["Id"].replace(
            prowler_string.format(account_id), ""
        )
        snapshot_id = snapshot_id.replace("_is_currently_not_encrypted_", "")

        # When
        uat.lambda_handler(event, context, securityhub=securityhub, ec2=ec2)

        # Then
        ec2.delete_snapshot.assert_called_with(SnapshotId=snapshot_id)
        securityhub.batch_update_findings.assert_called_with(
            FindingIdentifiers=[
                {
                    "Id": event["detail"]["findings"][0]["Id"],
                    "ProductArn": event["detail"]["findings"][0]["ProductArn"],
                },
            ],
            Note={"UpdatedBy": lambda_name, "Text": notice + snapshot_id,},
            Workflow={"Status": "RESOLVED"},
        )

    def test_client_error_list_access_keys(
        self, mock_env, event=test_event, context=context
    ):
        """Test error on remediation for cis14.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object

        Returns:
            No returns
        """
        import remediation.delete_unencrypted_snapshots as uat

        # Given
        securityhub = MagicMock()
        model = botocore.session.get_session().get_service_model("securityhub")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        securityhub.batch_update_findings.side_effect = exceptions.LimitExceededException(
            error_response={
                "Error": {
                    "Code": "LimitExceededException",
                    "Message": "LimitExceededException",
                }
            },
            operation_name="BatchUpdateFindings",
        )

        ec2 = MagicMock()

        # When
        try:
            uat.lambda_handler(event, context, securityhub=securityhub, ec2=ec2)
        except ClientError as e:
            if e.response["Error"]["Code"] == "LimitExceededException":
                # Then
                assert True
            else:
                # Then
                assert False


class TestPasswordPolicy:
    """Run tests for remediation of cis15 and cis11."""

    test_event = return_event(file_name="events/password_policy.json")
    context = return_context()
    notice = "Changed non compliant password policy"

    def test_batch_update_findings(
        self, mock_env, securityhub, event=test_event, notice=notice
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        lambda_name = "fake-lambda"
        finding_id = event["detail"]["findings"][0]["Id"]
        product_arn = event["detail"]["findings"][0]["ProductArn"]

        response = {
            "ProcessedFindings": [{"Id": finding_id, "ProductArn": product_arn},],
            "UnprocessedFindings": [],
        }
        expected_params = {
            "FindingIdentifiers": [{"Id": finding_id, "ProductArn": product_arn,},],
            "Note": {"Text": notice, "UpdatedBy": lambda_name,},
            "Workflow": {"Status": "RESOLVED"},
        }

        # When
        stubber.add_response("batch_update_findings", response, expected_params)
        with stubber:
            service_response = securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn,},],
                Note={"Text": notice, "UpdatedBy": lambda_name,},
                Workflow={"Status": "RESOLVED"},
            )

        # Then
        assert service_response == response

    def test_update_account_password_policy(
        self, mock_env, iam,
    ):
        """Test API call update_account_password_policy.

        Params:
            iam: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(iam)

        response = {}
        expected_params = {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "AllowUsersToChangePassword": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
            "HardExpiry": True,
        }

        # When
        stubber.add_response(
            "update_account_password_policy", response, expected_params
        )
        with stubber:
            service_response = iam.update_account_password_policy(
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

        # Then
        assert service_response == response

    def test_successful_remediation(
        self, mock_env, event=test_event, context=context, notice=notice
    ):
        """Test successful remediation for cis15 and cis11.

        Params:
            mock_env: mocked Lambda environment
            iam: mocked iam boto3 client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.password_policy as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = MagicMock()
        iam = MagicMock()

        # Give
        lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]

        # When
        uat.lambda_handler(event, context, iam=iam, securityhub=securityhub)

        # Then
        iam.update_account_password_policy.assert_called_with(
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

        securityhub.batch_update_findings.assert_called_with(
            FindingIdentifiers=[
                {
                    "Id": event["detail"]["findings"][0]["Id"],
                    "ProductArn": event["detail"]["findings"][0]["ProductArn"],
                },
            ],
            Note={"Text": notice, "UpdatedBy": lambda_name,},
            Workflow={"Status": "RESOLVED"},
        )

    def test_error_remediation(self, mock_env, event=test_event, context=context):
        """Test error remediation for cis15 and cis11.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.password_policy as uat  # Import here, so moto has the chance to mock all client initiations

        # Given
        securityhub = MagicMock()
        iam = MagicMock()
        model = botocore.session.get_session().get_service_model("iam")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        iam.update_account_password_policy.side_effect = exceptions.InvalidInputException(
            error_response={
                "Error": {"Code": "InvalidInputException", "Message": "Key not found",}
            },
            operation_name="UpdateAccountPasswordPolicy",
        )

        # When
        try:
            uat.lambda_handler(event, context, iam=iam, securityhub=securityhub)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                # Then
                assert True
            else:
                # Then
                assert False


class TestPutServerSideEncryption:
    """Run tests for remediation of s34."""

    test_event = return_event(file_name="events/put_server_side_encryption.json")
    context = return_context()
    s3_arn_prefix = "arn:aws:s3:::"
    notice = "Put SSE with KMS for "
    algo = "aws:kms"

    def test_batch_update_findings(
        self,
        mock_env,
        securityhub,
        event=test_event,
        notice=notice,
        s3_arn_prefix=s3_arn_prefix,
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        lambda_name = "fake-lambda"
        finding_id = event["detail"]["findings"][0]["Id"]
        product_arn = event["detail"]["findings"][0]["ProductArn"]
        s3_bucket_arn = event["detail"]["findings"][0]["Resources"][0]["Id"]
        s3_bucket_name = s3_bucket_arn.split(s3_arn_prefix)[1]

        response = {
            "ProcessedFindings": [{"Id": finding_id, "ProductArn": product_arn},],
            "UnprocessedFindings": [],
        }
        expected_params = {
            "FindingIdentifiers": [{"Id": finding_id, "ProductArn": product_arn,},],
            "Note": {"Text": notice + s3_bucket_name, "UpdatedBy": lambda_name,},
            "Workflow": {"Status": "RESOLVED"},
        }

        # When
        stubber.add_response("batch_update_findings", response, expected_params)
        with stubber:
            service_response = securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn,},],
                Note={"Text": notice + s3_bucket_name, "UpdatedBy": lambda_name,},
                Workflow={"Status": "RESOLVED"},
            )

        # Then
        assert service_response == response

    def test_put_bucket_encryption(
        self, mock_env, s3, event=test_event, algo=algo, s3_arn_prefix=s3_arn_prefix
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(s3)
        s3_bucket_arn = event["detail"]["findings"][0]["Resources"][0]["Id"]
        s3_bucket_name = s3_bucket_arn.split(s3_arn_prefix)[1]

        response = {}

        expected_params = {
            "Bucket": s3_bucket_name,
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algo,}},
                ]
            },
        }

        # When
        stubber.add_response("put_bucket_encryption", response, expected_params)
        with stubber:
            service_response = s3.put_bucket_encryption(
                Bucket=s3_bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algo,}},
                    ]
                },
            )

        # Then
        assert service_response == response

    def test_successful_remediation(
        self,
        mock_env,
        event=test_event,
        context=context,
        algo=algo,
        notice=notice,
        s3_arn_prefix=s3_arn_prefix,
    ):
        """Test successful remediation for s34.

        Params:
            mock_env: mocked Lambda environment
            s3: mocked s3 boto3 client
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.put_server_side_encryption as uat  # Import here, so moto has the chance to mock all client initiations

        securityhub = MagicMock()
        s3 = MagicMock()

        # Given
        lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]
        s3_bucket_arn = event["detail"]["findings"][0]["Resources"][0]["Id"]
        s3_bucket_name = s3_bucket_arn.split(s3_arn_prefix)[1]

        # When
        uat.lambda_handler(event, context, s3=s3, securityhub=securityhub)

        # Then
        s3.put_bucket_encryption.assert_called_with(
            Bucket=s3_bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algo,}},
                ]
            },
        )
        securityhub.batch_update_findings.assert_called_with(
            FindingIdentifiers=[
                {
                    "Id": event["detail"]["findings"][0]["Id"],
                    "ProductArn": event["detail"]["findings"][0]["ProductArn"],
                },
            ],
            Note={"Text": notice + s3_bucket_name, "UpdatedBy": lambda_name,},
            Workflow={"Status": "RESOLVED"},
        )

    def test_error_remediation(self, mock_env, event=test_event, context=context):
        """Test error remediation for s34.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object
        """
        import remediation.put_server_side_encryption as uat  # Import here, so moto has the chance to mock all client initiations

        # Given
        securityhub = MagicMock()
        s3 = MagicMock()
        model = botocore.session.get_session().get_service_model("s3")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        s3.put_bucket_encryption.side_effect = exceptions.NoSuchBucket(
            error_response={
                "Error": {"Code": "NoSuchBucket", "Message": "Bucket not found",}
            },
            operation_name="PutBucketEncryption",
        )

        # When
        try:
            uat.lambda_handler(event, context, s3=s3, securityhub=securityhub)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":
                # Then
                assert True
            else:
                # Then
                assert False


class TestPutSSLCommunication:
    """Run tests for remediation of s35."""

    test_event = return_event(file_name="events/put_ssl_communication.json")
    context = return_context()
    s3_arn_bucket = "arn:aws:s3:::{}"
    s3_arn_object = "arn:aws:s3:::{}/*"
    notice = "Put SSL-Communication-Only for "
    bucket_policy_condition = {"Bool": {"aws:SecureTransport": "false"}}

    def test_put_bucket_policy(
        self,
        s3,
        s3_arn_bucket=s3_arn_bucket,
        s3_arn_object=s3_arn_object,
        bucket_policy_condition=bucket_policy_condition,
    ):
        """Test API call put_bucket_policy.

        Params:
            s3: mocked s3 boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(s3)
        bucket_name = "fake-bucket"
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSSLRequestsOnly",
                    "Action": "s3:*",
                    "Effect": "Deny",
                    "Resource": [
                        s3_arn_bucket.format(bucket_name),
                        s3_arn_object.format(bucket_name),
                    ],
                    "Condition": bucket_policy_condition,
                    "Principal": "*",
                }
            ],
        }
        bucket_policy = json.dumps(bucket_policy)

        expected_params = {
            "Bucket": bucket_name,
            "Policy": bucket_policy,
        }
        response = {
            "ResponseMetadata": {"foo": "bar",},
        }
        # When
        stubber.add_response("put_bucket_policy", response, expected_params)
        with stubber:
            service_response = s3.put_bucket_policy(
                Bucket=bucket_name, Policy=bucket_policy
            )

        # Then
        assert service_response == response

    def test_get_bucket_policy(
        self,
        s3,
        s3_arn_bucket=s3_arn_bucket,
        s3_arn_object=s3_arn_object,
        bucket_policy_condition=bucket_policy_condition,
    ):
        """Test API call get_bucket_policy.

        Params:
            s3: mocked s3 boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(s3)
        bucket_name = "fake-bucket"
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSSLRequestsOnly",
                    "Action": "s3:*",
                    "Effect": "Deny",
                    "Resource": [
                        s3_arn_bucket.format(bucket_name),
                        s3_arn_object.format(bucket_name),
                    ],
                    "Condition": bucket_policy_condition,
                    "Principal": "*",
                }
            ],
        }
        bucket_policy = json.dumps(bucket_policy)
        expected_params = {"Bucket": bucket_name}
        response = {
            "Policy": bucket_policy,
        }
        # When
        stubber.add_response("get_bucket_policy", response, expected_params)
        with stubber:
            service_response = s3.get_bucket_policy(Bucket=bucket_name)

        # Then
        assert service_response == response

    def test_batch_update_findings(
        self, mock_env, securityhub, event=test_event, notice=notice
    ):
        """Test API call batch_update_findings.

        Params:
            securityhub: mocked iam boto3 client

        Returns:
            No returns
        """
        # Give
        stubber = Stubber(securityhub)
        bucket_name = "fake-bucket"
        lambda_name = "fake-lambda"
        finding_id = event["detail"]["findings"][0]["Id"]
        product_arn = event["detail"]["findings"][0]["ProductArn"]
        response = {
            "ProcessedFindings": [{"Id": finding_id, "ProductArn": product_arn},],
            "UnprocessedFindings": [],
        }
        expected_params = {
            "FindingIdentifiers": [{"Id": finding_id, "ProductArn": product_arn,},],
            "Note": {"Text": notice + bucket_name, "UpdatedBy": lambda_name,},
            "Workflow": {"Status": "RESOLVED"},
        }

        # When
        stubber.add_response("batch_update_findings", response, expected_params)
        with stubber:
            service_response = securityhub.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn,},],
                Note={"Text": notice + bucket_name, "UpdatedBy": lambda_name,},
                Workflow={"Status": "RESOLVED"},
            )

        # Then
        assert service_response == response

    def test_successful_remediation(
        self,
        mock_env,
        event=test_event,
        context=context,
        notice=notice,
        s3_arn_bucket=s3_arn_bucket,
        s3_arn_object=s3_arn_object,
        bucket_policy_condition=bucket_policy_condition,
    ):
        """Test successful remediation for s35.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object

        Returns:
            No returns
        """
        import remediation.put_ssl_communication as uat

        securityhub = MagicMock()
        s3 = MagicMock()  # moto s3 does not support put_bucket_policy() :(
        lambda_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]

        # Given
        s3_bucket_name = "test123"
        s3_action = "s3:GetObject"

        uncompliant_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FooBar1",
                    "Action": s3_action,
                    "Effect": "Allow",
                    "Resource": [
                        s3_arn_bucket.format(s3_bucket_name),
                        s3_arn_object.format(s3_bucket_name),
                    ],
                    "Principal": {"AWS": ["arn:aws:iam::012345678912:root"]},
                },
                {
                    "Sid": "FooBar2",
                    "Action": s3_action,
                    "Effect": "Allow",
                    "Resource": [
                        s3_arn_bucket.format(s3_bucket_name),
                        s3_arn_object.format(s3_bucket_name),
                    ],
                    "Principal": {"AWS": ["arn:aws:iam::012345678913:root"]},
                },
            ],
        }
        s3.get_bucket_policy.return_value = {"Policy": json.dumps(uncompliant_policy)}

        event["detail"]["findings"][0]["Resources"][0]["Id"] = (
            "arn:aws:s3:::" + s3_bucket_name
        )

        bucket_policy_new = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FooBar1",
                    "Action": s3_action,
                    "Effect": "Allow",
                    "Resource": [
                        s3_arn_bucket.format(s3_bucket_name),
                        s3_arn_object.format(s3_bucket_name),
                    ],
                    "Principal": {"AWS": ["arn:aws:iam::012345678912:root"]},
                },
                {
                    "Sid": "FooBar2",
                    "Action": s3_action,
                    "Effect": "Allow",
                    "Resource": [
                        s3_arn_bucket.format(s3_bucket_name),
                        s3_arn_object.format(s3_bucket_name),
                    ],
                    "Principal": {"AWS": ["arn:aws:iam::012345678913:root"]},
                },
                {
                    "Sid": "AllowSSLRequestsOnly",
                    "Action": "s3:*",
                    "Effect": "Deny",
                    "Resource": [
                        s3_arn_bucket.format(s3_bucket_name),
                        s3_arn_object.format(s3_bucket_name),
                    ],
                    "Condition": bucket_policy_condition,
                    "Principal": "*",
                },
            ],
        }
        event["detail"]["findings"][0]["Resources"][0]["Id"] = (
            "arn:aws:s3:::" + s3_bucket_name
        )

        # When
        uat.lambda_handler(event, context, s3=s3, securityhub=securityhub)

        # Then
        s3.get_bucket_policy.assert_called_with(Bucket=s3_bucket_name)

        s3.put_bucket_policy.assert_called_with(
            Bucket=s3_bucket_name, Policy=json.dumps(bucket_policy_new)
        )

        securityhub.batch_update_findings.assert_called_with(
            FindingIdentifiers=[
                {
                    "Id": event["detail"]["findings"][0]["Id"],
                    "ProductArn": event["detail"]["findings"][0]["ProductArn"],
                },
            ],
            Note={"Text": notice + s3_bucket_name, "UpdatedBy": lambda_name,},
            Workflow={"Status": "RESOLVED"},
        )

    def test_error_remediation(self, mock_env, event=test_event, context=context):
        """Test successful remediation for s35.

        Params:
            mock_env: mocked Lambda environment
            event: Lambda event object
            context: Lambda context object

        Returns:
            No returns
        """
        import remediation.put_ssl_communication as uat

        # Given
        s3 = MagicMock()
        model = botocore.session.get_session().get_service_model("s3")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)
        s3.get_bucket_policy.side_effect = exceptions.NoSuchBucket(
            error_response={
                "Error": {
                    "Code": "NoSuchBucketPolicy",
                    "Message": "Bucket does not exist",
                }
            },
            operation_name="GetBucketPolicy",
        )

        securityhub = MagicMock()

        # When
        try:
            uat.lambda_handler(event, context, securityhub=securityhub, s3=s3)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                # Then
                assert True
            else:
                # Then
                assert False
