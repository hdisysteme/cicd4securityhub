from aws_cdk import core

from securityhub.auto_ops import AutoSecOps
from securityhub.pipeline import Pipeline

app = core.App()

cicd = Pipeline(
    app,
    id="cicd-4-securityhub",
    env=core.Environment(account="12345678910", region="eu-central-1"),
)
core.Tags.of(cicd).add("Name", "Security Hub App")

auto_ops = AutoSecOps(app, "auto-security-operations",)
core.Tags.of(auto_ops).add("Name", "Security Hub App")

app.synth()
