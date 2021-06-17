import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="securityhub",
    version="0.0.1",
    description="A CDK app to provision Custom Actions as well as Auto Remediation within the Security Hub app service",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="author",
    package_dir={"": "securityhub"},
    packages=setuptools.find_packages(where="securityhub"),
    install_requires=[
        "pytest-cov",
        "boto3",
        "aws-cdk.core==1.105.0",
        "aws-cdk.aws_applicationautoscaling==1.105.0",
        "aws-cdk.aws_cloudformation==1.105.0",
        "aws-cdk.aws_ec2==1.105.0",
        "aws-cdk.aws_ecr==1.105.0",
        "aws-cdk.aws_ecs==1.105.0",
        "aws-cdk.aws_ecs_patterns==1.105.0",
        "aws-cdk.aws_iam==1.105.0",
        "aws-cdk.aws_lambda==1.105.0",
        "aws-cdk.aws_logs==1.105.0",
        "aws-cdk.aws_securityhub==1.105.0",
        "aws-cdk.aws_codebuild==1.105.0",
        "aws-cdk.aws_codecommit==1.105.0",
        "aws-cdk.aws_codepipeline==1.105.0",
        "aws-cdk.aws_codepipeline_actions==1.105.0",
        "aws-cdk.pipelines==1.105.0",
        "pydocstyle",
        "pre-commit",
        "flake8",
    ],
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
)
