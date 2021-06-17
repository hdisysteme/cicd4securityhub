from aws_cdk import aws_applicationautoscaling as _applicationautoscaling
from aws_cdk import aws_cloudformation as _cfn
from aws_cdk import aws_ec2 as _ec2
from aws_cdk import aws_ecr as _ecr
from aws_cdk import aws_ecs as _ecs
from aws_cdk import aws_ecs_patterns as _ecs_patterns
from aws_cdk import aws_iam as _iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as _logs
from aws_cdk import aws_securityhub as _securityhub
from aws_cdk import core

from helper import create_remediation_lambdas


class EnableProwlerScanning(_cfn.NestedStack):
    """Enable Security Hub and Prowler Integration.

    Params:
        core.Stack: CDK stack submitted by app.py
    Returns:
        No returns
    """

    def __init__(self, scope, id: str) -> None:
        """Create the resources for the Pipeline stack.

        Params:
            self: Submitted from AutoSecOpsCIS - self as default
            scope: core.Construct as default
            id: Name of the stack, injected by app.py and pipeline.py
        Returns:
            No returns
        """
        super().__init__(scope, id)

        ################################
        # Scheduled Fargate Task for Prowler
        ################################

        vpc = _ec2.Vpc(self, id="prowler-vpc", cidr="10.0.0.0/16")

        cluster = _ecs.Cluster(self, id="prowler-checks-cluster", vpc=vpc,)

        docker_repo = _ecr.Repository(self, id="prowler-repo",)

        schedule_fargate_task = _ecs_patterns.ScheduledFargateTaskImageOptions(
            image=_ecs.ContainerImage.from_ecr_repository(repository=docker_repo,),
            cpu=2048,
            memory_limit_mib=4096,
        )

        fargate_security_service = _ecs_patterns.ScheduledFargateTask(
            self,
            id="scheduled-prowler-task",
            schedule=_applicationautoscaling.Schedule.cron(
                hour="5", minute="0", day="*/7", month="*", year="*",
            ),
            cluster=cluster,
            vpc=vpc,
            subnet_selection=_ec2.SubnetSelection(subnet_type=_ec2.SubnetType.PUBLIC),
            desired_task_count=1,
            scheduled_fargate_task_image_options=schedule_fargate_task,
        )

        fargate_security_service.task_definition.task_role.add_managed_policy(
            policy=_iam.ManagedPolicy.from_managed_policy_arn(
                self,
                id="prowler-security-audit",
                managed_policy_arn="arn:aws:iam::aws:policy/SecurityAudit",
            )
        )

        fargate_security_service.task_definition.task_role.add_managed_policy(
            policy=_iam.ManagedPolicy.from_managed_policy_arn(
                self,
                id="prowler-view-only-access",
                managed_policy_arn="arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
            )
        )

        fargate_security_service.task_definition.add_to_task_role_policy(
            statement=_iam.PolicyStatement(
                effect=_iam.Effect.ALLOW,
                actions=[
                    "dax:ListTables",
                    "ds:ListAuthorizedApplications",
                    "ds:DescribeRoles",
                    "ec2:GetEbsEncryptionByDefault",
                    "ecr:Describe*",
                    "support:Describe*",
                    "tag:GetTagKeys",
                    "sts:GetCallerIdentity",
                    "ec2:DescribeRegions",
                    "iam:GenerateCredentialReport",
                    "securityhub:BatchImportFindings",
                    "securityhub:GetFindings",
                ],
                resources=["*"],
            )
        )

        ################################
        # Security Hub
        ################################

        _securityhub.CfnHub(
            self, id="security-hub",
        )

        ################################
        # Lambda Enable Prowler
        ################################

        enable_prowler_statement = _iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            actions=["securityhub:EnableImportFindingsForProduct",],
            resources=[
                "arn:aws:securityhub:{}:{}:hub/default".format(
                    core.Aws.REGION, core.Aws.ACCOUNT_ID
                ),
            ],
        )

        with open("./src/lambda/custom_resource/enable_prowler.py") as lambda_inline:
            inline_code = lambda_inline.read()

        lambda_enable_prowler = _lambda.Function(
            self,
            id="enable-prowler",
            handler="enable_prowler.enable_integration",
            code=_lambda.Code.from_inline(inline_code),
            memory_size=128,
            runtime=_lambda.Runtime.PYTHON_3_7,
            timeout=core.Duration.seconds(300),
            retry_attempts=1,
            log_retention=_logs.RetentionDays.THREE_MONTHS,
        )

        lambda_enable_prowler.add_to_role_policy(enable_prowler_statement)

        core.CustomResource(
            self,
            id="cr-enable-prowler",
            service_token=lambda_enable_prowler.function_arn,
            removal_policy=core.RemovalPolicy.DESTROY,
            properties={
                "IntegrationARN": "arn:aws:securityhub:{}::product/prowler/prowler".format(
                    core.Aws.REGION
                ),
                "ServiceToken": lambda_enable_prowler.function_arn,
            },
        )


class RemediationStack(_cfn.NestedStack):
    """Enable Framework related remediation.

    Params:
        core.Stack: CDK stack submitted by app.py
    Returns:
        No returns
    """

    def __init__(self, scope, id, remediation_list: list):
        """Create the resources for remediating findings.

        Params:
            self: Submitted from AutoSecOps - self as default
            scope: core.Construct as default
            id: Name of the stack, injected by app.py and pipeline.py
            remediation_list: List with remediation Lambdas, injected by parent
        Returns:
            No returns
        """
        super().__init__(scope, id)

        create_remediation_lambdas(
            scope=self,
            lambda_dicts_list=remediation_list,
            securityhub_policy=_iam.PolicyStatement(
                effect=_iam.Effect.ALLOW,
                actions=["securityhub:BatchUpdateFindings"],
                resources=["*"],
            ),
        )


class AutoSecOps(core.Stack):
    """Create global resources consumed by AWS and remediation stacks.

    Params:
        core.Stack: CDK stack submitted by app.py
    Returns:
        No returns
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        """Create the resources for remediating findings and the Prowler integration in nested stacks.

        Params:
            self: Submitted from AutoSecOpsCIS - self as default
            scope: core.Construct as default
            id: Name of the stack, injected by app.py and hd_pipeline.py
        Returns:
            No returns
        """
        super().__init__(scope, id, **kwargs)

        # #######################################
        # Create Config Objects for a Nested Stack
        # #######################################

        cis1314_lambda = {
            "name": "CIS 1.4",
            "id": "cis14",
            "description": "Remediates CIS 1.3. and 1.4 by deleting IAM Keys over 90 Days Old",
            "policies": [
                _iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=[
                        "iam:DeleteAccessKey",
                        "iam:UpdateAccessKey",
                        "iam:ListAccessKeys",
                    ],
                    resources=["*"],
                )
            ],
            "path": "access_key_deletion",
            "environment_variables": None,
            "filter_id": [
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.4"
            ],
        }

        cis1511_lambda = {
            "name": "CIS 1.5-11",
            "id": "cis1591011",
            "description": "Remediates CIS Checks 1.5, 1.9 and 1.10 through 1.11 by establishing a CIS Compliant strong Password Policy",
            "policies": [
                _iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["iam:UpdateAccountPasswordPolicy",],
                    resources=["*"],
                )
            ],
            "path": "password_policy",
            "environment_variables": None,
            "filter_id": [
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.5",
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.9",
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.10",
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.11",
            ],
        }

        cis_list = [
            cis1314_lambda,
            cis1511_lambda,
        ]

        s35_lambda = {
            "name": "S3.5",
            "id": "s35",
            "description": "Remediates S3.5 by enforcing Secure Socket Layer (SSL) for every Bucket.",
            "policies": [
                _iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["s3:PutBucketPolicy", "s3:GetBucketPolicy"],
                    resources=["*"],
                )
            ],
            "path": "put_ssl_communication",
            "environment_variables": None,
            "filter_id": ["aws-foundational-security-best-practices/v/1.0.0/S3.5"],
        }

        s34_lambda = {
            "name": "S3.4",
            "id": "s34",
            "description": "Remediates S 3.4 by enabling server side encryption by KMS on S3 Buckets.",
            "policies": [
                _iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["s3:PutEncryptionConfiguration",],
                    resources=["*"],
                )
            ],
            "path": "put_server_side_encryption",
            "environment_variables": None,
            "filter_id": ["aws-foundational-security-best-practices/v/1.0.0/S3.4"],
        }

        aws_sec_frame_list = [
            s35_lambda,
            s34_lambda,
        ]

        prowler_729_lambda = {
            "name": "Prowler 7.29",
            "id": "prowler729",
            "description": "Remediates Prowler 7.29 by deleting/terminating unencrypted EC2 instances/EBS volumes",
            "policies": [
                _iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["ec2:TerminateInstances", "ec2:DeleteVolume",],
                    resources=["*"],
                )
            ],
            "path": "delete_unencrypted_ebs_volumes",
            "environment_variables": [
                {"key": "ACCOUNT_ID", "value": core.Aws.ACCOUNT_ID}
            ],
            "filter_id": ["prowler-extra729"],
        }

        prowler_740_lambda = {
            "name": "Prowler 7.40",
            "id": "prowler740",
            "description": "Remediates Prowler 7.40 by deleting unencrypted Snapshots",
            "policies": [
                _iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["ec2:DeleteSnapshot",],
                    resources=["*"],
                )
            ],
            "path": "delete_unencrypted_snapshots",
            "environment_variables": [
                {"key": "ACCOUNT_ID", "value": core.Aws.ACCOUNT_ID}
            ],
            "filter_id": ["prowler-extra740"],
        }

        prowler_list = [
            prowler_729_lambda,
            prowler_740_lambda,
        ]

        # #######################################
        # Create Prowler and Security Hub integration in nested Stack
        # #######################################

        print("Building Prowler and Security Hub")
        prowler = EnableProwlerScanning(self, id="enable-security-hub",)
        core.Tags.of(prowler).add("Name", "Security Hub App")

        print("Lambdas in AWS Security Framework Stack", len(aws_sec_frame_list))
        aws_1 = RemediationStack(
            self,
            id="aws-security-best-practises-remediation",
            remediation_list=aws_sec_frame_list,
        )
        aws_1.add_dependency(prowler)
        core.Tags.of(aws_1).add("Name", "Security Hub App")

        print("Lambdas in CIS Stack", len(cis_list))
        cis_1 = RemediationStack(self, id="cis-remediation", remediation_list=cis_list,)
        cis_1.add_dependency(aws_1)
        core.Tags.of(cis_1).add("Name", "Security Hub App")

        print("Lambdas in Prowler Stack", len(cis_list))
        prowler_1 = RemediationStack(
            self, id="prowler-remediation}", remediation_list=prowler_list,
        )
        prowler_1.add_dependency(cis_1)
        core.Tags.of(prowler_1).add("Name", "Security Hub App")
