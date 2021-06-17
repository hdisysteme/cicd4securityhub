from aws_cdk import aws_events as _events
from aws_cdk import aws_events_targets as _events_targets
from aws_cdk import aws_iam as _iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as _logs
from aws_cdk import core


def create_remediation_lambdas(
    scope, lambda_dicts_list: list, securityhub_policy: any,
):
    """Deploys an End-2-End Remediation Lambda.

    Args:
        scope: self
        lambda_dicts_list: A list with dicts with configuration parameters
        securityhub_policy: SecurityHub Policy
    Returns:
        no returns
    """
    securityhub_cat_policy = _iam.PolicyStatement(
        effect=_iam.Effect.ALLOW,
        actions=["securityhub:CreateActionTarget", "securityhub:DeleteActionTarget"],
        resources=["*"],
    )

    # Create Action Target Lambda

    lambda_create_action_target = _lambda.Function(
        scope,
        id="create-action-target",
        handler="create_action_target.create_action_target",
        code=_lambda.Code.from_asset(
            "./src/lambda/custom_resource/create_action_target/"
        ),
        memory_size=128,
        runtime=_lambda.Runtime.PYTHON_3_7,
        timeout=core.Duration.seconds(300),
        initial_policy=[securityhub_cat_policy],
        retry_attempts=1,
        log_retention=_logs.RetentionDays.THREE_MONTHS,
    )

    lambda_create_action_target.add_environment(
        key="ACCOUNT_ID", value=core.Aws.ACCOUNT_ID,
    )

    for i in lambda_dicts_list:
        name = "{}".format(i["name"])
        uuid = "{}".format(i["id"])
        print("Lambda Name ", name, " ID ", uuid)
        assert len(name) < 20, "Error: Name is longer then 20 characters ... {}".format(
            name
        )
        assert len(uuid) < 20, "Error: Id is longer then 20 characters ... {}".format(
            id
        )
        assert (
            uuid.isalnum() is True
        ), "Error: Id allows only alphanumeric characters ... {}".format(id)

        core.CustomResource(
            scope,
            id="{}-cr".format(i["id"]),
            service_token=lambda_create_action_target.function_arn,
            removal_policy=core.RemovalPolicy.DESTROY,
            properties={
                "Name": name,
                "Description": i["description"],
                "Id": uuid,
                "ServiceToken": lambda_create_action_target.function_arn,
            },
        )

        # Inject Lambdas as inline code to avoid parallel CodeBuild runs
        with open(
            "./src/lambda/remediation/{}.py".format(i["path"]), "r"
        ) as lambda_inline:
            inline_code = lambda_inline.read()

        print("{}-Lambda".format(i["id"]))

        lambda_function = _lambda.Function(
            scope,
            id="{}-Lambda".format(i["id"]),
            code=_lambda.Code.from_inline(inline_code),
            handler="index.lambda_handler",
            runtime=_lambda.Runtime.PYTHON_3_7,
            memory_size=256,
            timeout=core.Duration.seconds(60),
            initial_policy=[securityhub_policy],
            log_retention=_logs.RetentionDays.THREE_MONTHS,
        )

        if i["policies"] is not None:
            for policy_statement in i["policies"]:
                lambda_function.add_to_role_policy(policy_statement)

        if i["environment_variables"] is not None:
            for env_var in i["environment_variables"]:
                try:
                    lambda_function.add_environment(
                        key=env_var["key"], value=env_var["value"],
                    )
                except IndexError:
                    print("Eor while assigning environment variables")

        _events.Rule(
            scope,
            id="{}-rule-custom-action".format(i["id"],),
            description=i["description"],
            enabled=True,
            targets=[_events_targets.LambdaFunction(lambda_function)],
            event_pattern=_events.EventPattern(
                detail_type=["Security Hub Findings - Custom Action"],
                source=["aws.securityhub"],
                resources=[
                    "arn:aws:securityhub:{}:{}:action/custom/{}".format(
                        core.Aws.REGION, core.Aws.ACCOUNT_ID, uuid
                    )
                ],
            ),
        )

        if i["filter_id"] is not None:
            _events.Rule(
                scope,
                id="{}-role-auto-remediation".format(i["id"]),
                description=i["description"],
                enabled=True,
                targets=[_events_targets.LambdaFunction(lambda_function)],
                event_pattern=_events.EventPattern(
                    detail_type=["Security Hub Findings - Imported"],
                    source=["aws.securityhub"],
                    detail={
                        "findings": {
                            "GeneratorId": i["filter_id"],
                            "Compliance": {"Status": ["FAILED"]},
                            "Workflow": {"Status": ["NEW"]},
                        }
                    },
                ),
            )
