from aws_cdk import core

from securityhub.auto_ops import AutoSecOps
from securityhub.pipeline import Pipeline

app = core.App()

# TODO: Insert your AWS account id
cicd = Pipeline(
    app,
    id="cicd-4-securityhub",
    env=core.Environment(account="800524020870", region="eu-central-1"),
)
core.Tags.of(cicd).add("Name", "Security Hub App")

auto_ops = AutoSecOps(app, "auto-security-operations",)
core.Tags.of(auto_ops).add("Name", "Security Hub App")

app.synth()
