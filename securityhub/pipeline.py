from aws_cdk import aws_codebuild as _codebuild
from aws_cdk import aws_codecommit as _code
from aws_cdk import aws_codepipeline as _codepipeline
from aws_cdk import aws_codepipeline_actions as _codepipeline_actions
from aws_cdk import aws_ecr as _ecr
from aws_cdk import core
from aws_cdk import pipelines as _pipelines

from auto_ops import AutoSecOps


class DevSecurityOpsStage(core.Stage):
    """Create Dev Stage for CDK pipeline.

    Params:
        core.Stage: CDK stack submitted by app.py
    Returns:
        No returns
    """

    def __init__(self, scope, id, *, env=None, outdir=None):
        """Create the DEV stage for the DevSecOps pipeline.

        Params:
            core.Stage: CDK stack submitted by app.py
            AutoSecOps:
                Create global resources consumed by other stacks,
                start nested stacks for Prowler, Security Hub and remediation integrations
        Returns:
            No returns
        """
        super().__init__(scope, id, env=env, outdir=outdir)
        AutoSecOps(self, "FindingsRemediation")


class Pipeline(core.Stack):
    """Create the DevSecOps pipeline.

    Params:
        core.Stage: CDK stack submitted by app.py
    Returns:
        No returns
    """

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        """Create the actually resources for the Pipeline stack.

        Params:
            self: Submitted from AutoSecOpsCIS - self as default
            scope: core.Construct as default
            id: Name of the stack, injected by app.py and hd_pipeline.py
        Returns:
            No returns
        """
        super().__init__(scope, id, **kwargs)

        ################################
        # CDK Pipeline
        ################################

        ################################
        # ECR Repository
        ################################

        docker_repo = _ecr.Repository(self, id="ECR-Prowler", image_scan_on_push=True,)

        core.CfnOutput(
            self, id="prowler-repo", value=docker_repo.repository_name,
        )

        ################################
        # Codecommit
        ################################

        git = _code.Repository(
            self,
            id="git",
            repository_name="security-operations",
            description="Holds Security Hub and Remediation App",
        )

        source_output = _codepipeline.Artifact()
        cloud_assembly_artifact = _codepipeline.Artifact()

        cicd = _pipelines.CdkPipeline(
            self,
            id="cicd",
            cloud_assembly_artifact=cloud_assembly_artifact,
            pipeline_name="dev-sec-ops-pipeline",
            source_action=_codepipeline_actions.CodeCommitSourceAction(
                action_name="source-control",
                output=source_output,
                repository=git,
                variables_namespace="source",
                branch="master",
            ),
            # https://github.com/aws/aws-cdk/issues/10464
            synth_action=_pipelines.SimpleSynthAction(
                source_artifact=source_output,
                cloud_assembly_artifact=cloud_assembly_artifact,
                install_commands=[
                    "npm install -g aws-cdk",
                    "pip install botocore --upgrade",
                    "pip install boto3 --upgrade",
                    "pip install -U -r requirements.txt --no-cache-dir",
                    "pytest",
                ],
                synth_command="cdk synth",
                environment={
                    "privileged": True,
                    "build_image": _codebuild.LinuxBuildImage.AMAZON_LINUX_2_3,
                },
            ),
            self_mutating=True,
        )

        ################################
        # CDK Pipeline - Stages
        ################################

        print("Building/Updating Stage")

        # TODO: Insert your AWS account id
        stage = DevSecurityOpsStage(
            self,
            id="sec-ops-utilities",
            env=core.Environment(account="800524020870", region="eu-central-1"),
        )
        cicd.add_application_stage(stage)

        ################################
        # CDK Outputs
        ################################

        core.CfnOutput(self, id="git-https-url", value=git.repository_clone_url_http)

        core.CfnOutput(self, id="git-ssh-url", value=git.repository_clone_url_ssh)

        core.CfnOutput(
            self, id="git-grc-url", value=git.repository_clone_url_grc,
        )
