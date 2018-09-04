AWS Codepipeline Creator
========================

Features
========

aws-pipeline-creator creates a aws codepipeline cloudformation stack,
and points to a build specifical file in the code repository

Installation
============

aws-pipeline-creator is on PyPI so all you need is:

    $ pip install aws-pipeline-creator

Example
=======

Getting help

    $ pipeline-creator upsert --help
    Usage: pipeline-creator upsert [OPTIONS]

       primary function for creating a bucket :return:

     Options:
       -v, --version TEXT  code version
       -d, --dryrun        dry run
       -y, --yaml          YAML template (deprecated - YAMLness is now detected at
                           run-time
       --no-poll           Start the stack work but do not poll
       -i, --ini TEXT      INI file with needed information  [required]
       --debug             Turn on debugging
       --help              Show this message and exit.

    pipeline-creator upsert -i config/my.ini

Example Ini file

    [environment]
    # This is a general bucket where the cloudformation template will be uploaded to prior to deployment
    bucket = cloudformation-templates
    # The name you want on the cloudformation stack
    stack_name = my-stack-name
    region = us-east-1
    profile = my-aws-profile


    [tags]
    # These are the tags which will be automatically applied to resources
    Name = test-codepipeline
    ResourceOwner = my_boss
    Project = MyCoolProject
    DeployedBy = me

    [parameters]
    # CodeCommit repository name
    RepositoryName = repo_name
    # Codecommit repository branch name
    RepositoryBranchName = master
    # A project name or code
    Project = test
    ProjectDescription =  test
    # The role which is utilized for the code pipeline, see below for an example role policy
    BuildServiceRole = arn:aws:iam::123456789:role/AWSCodebuildRole
    BuildProjectName = MyBuild
    Subnets = subnet-c1234556
    SecurityGroups = sg-123456
    Timeout = 60
    # The location in the repository where the build spec file is located
    BuildspecFile = folder/buildspec.yml
    # Set the environment code.  This is how developers code deployments in the build spec.
    # If EnvCode = dev, then do this, if EnvCode is prod, then do that
    EnvironmentCode = dev
    VpcId = vpc-123456
    # This is a bucket where the builds from each stage in the build process are stored
    DeploymentBucketName = codepipeline-deployments
    # The image to utilize
    # You can also use default AWS images from https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-available.html
    # Example: Image = aws/codebuild/docker:17.09.0
    Image = 123456789.dkr.ecr.us-east-1.amazonaws.com/codepipeline:latest


    [meta-parameters]
    # These are the metadata parameters which are applied to the template via jinja2
    ProjectName = myproject

Demonstration
=============

<p><a target="_blank" rel="noopener noreferrer" href="https://github.com/rubelw/aws_pipeline_creator/blob/master/images/awspipeline.gif"><img src="https://github.com/rubelw/aws_pipeline_creator/raw/master/images/awspipeline.gif" alt="AWS pipeline tutorial" style="max-width:100%;"></a></p>



Example Template

Just add more stages as needed.

``` {.sourceCode .console}

		"AWSCodebuildRole": {
			"Type": "AWS::IAM::Role",
			"Properties": {
				"RoleName": "AWSCodebuildRole",
				"AssumeRolePolicyDocument": {
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Principal": {
							"Service": [
								"codebuild.amazonaws.com",
								"codepipeline.amazonaws.com",
								"events.amazonaws.com"
							]
						},
						"Action": [
							"sts:AssumeRole"
						]
					}]
				},
				"ManagedPolicyArns": [
					"arn:aws:iam::123456789:policy/CustomPolicy",
					"arn:aws:iam::aws:policy/AmazonEC2FullAccess",
					"arn:aws:iam::aws:policy/AWSCodeCommitReadOnly",
					"arn:aws:iam::aws:policy/CloudFrontFullAccess",
					"arn:aws:iam::aws:policy/AmazonSSMFullAccess"
				],
				"Policies": [{
						"PolicyName": "AllowKmsDecryptForSSMParameterStore",
						"PolicyDocument": {
							"Version": "2012-10-17",
							"Statement": [{
								"Effect": "Allow",
								"Action": [
									"kms:Decrypt"
								],
								"Resource": [
									"arn:aws:kms:us-east-1:123456789:key/123-456-789"
								]
							}]
						}
					},
					{
						"PolicyName": "AssumeOwnRole",
						"PolicyDocument": {
							"Version": "2012-10-17",
							"Statement": [{
								"Effect": "Allow",
								"Action": [
									"sts:AssumeRole"
								],
								"Resource": [
									"arn:aws:iam::123456789:role/AWSCodebuildRole",
									"arn:aws:iam::123456789:assumedrole/AWSCodebuildRole"
								]
							}]
						}
					},
					{
						"PolicyName": "AssumeBuildRoleInAnotherAccount",
						"PolicyDocument": {
							"Version": "2012-10-17",
							"Statement": [{
								"Effect": "Allow",
								"Action": [
									"sts:AssumeRole"
								],
								"Resource": [
									"arn:aws:iam::111111111111:role/AWSCodebuildRole",
									"arn:aws:sts::111111111111:assumed-role/AWSCodebuildRole/*"
								]
							}]
						}
					},
					{
						"PolicyName": "ecs-service",
						"PolicyDocument": {
							"Version": "2012-10-17",
							"Statement": [{
								"Action": [
									"ecr:*",
									"codebuild:*",
									"codepipeline:*",
									"s3:*",
									"codecommit:*",
									"logs:*",
									"cloudwatch:*",
									"lambda:*",
									"athena:*"
								],
								"Resource": "*",
								"Effect": "Allow"
							}]
						}
					}
				]
			}
		}
```