AWS Role Creator
========================

Features
========

aws-role-creator creates an aws role.

The primary purpose is to create roles for projects, which automatically allows them access to various AWS
resources based-on their project name.  If the project name is 'test', they can only access resources which
begin with 'TEST' or 'test'



Installation
============

aws-role-creator is on PyPI so all you need is:

    $ pip install aws-role-creator

Example
=======

Getting help

    $ role-creator upsert --help
    Usage: role-creator upsert [OPTIONS]

      Creates a new role

    Options:
      -v, --version TEXT              code version
      -d, --dryrun                    dry run
      --no-poll                       Start the stack work but do not poll
      -i, --ini TEXT                  INI file with needed information
      -n, --project-name TEXT         project name
      -e, --environment-abbreviation TEXT
                                      environment abbreviation (i.e. dev, pd,
                                      sb,etc)
      -a, --aws-account-number TEXT   aws account number for role or account
                                      number for aws account role will jump to if
                                      project_role_jump_account
      -b, --bucket TEXT               bucket to upload cf template
      -t, --template-type TEXT        template type - whether a project_role or
                                      project_role_jump_account
      -r, --region TEXT               aws region
      -p, --aws-profile TEXT          aws profile
      -w, --aws-resources TEXT        comma delimited list of aws resources the
                                      role will have access to. Includes: ec2,clou
                                      dformation,s3,ecs,support,events,kms,waf,sns
                                      ,states,iam,elasticloadbalancing,cloudwatch,
                                      cloudfront,elasticbeanstalk,ecr,autoscaling,
                                      dynamodb,sqs,acm,route53,codebuild,codepipel
                                      ine,ssm,batch,apigateway,logs,elasticmapredu
                                      ce
      -m, --template TEXT             cloudformation template path/name
      --debug                         Turn on debugging
      --help                          Show this message and exit.


Background

    If you have multiple AWS accounts, such as one for Dev, one for , QA, and one for Prod. Then you usually have an AWS jump account where
    users can login, and then assume roles in to other AWS accounts - this is the purpose of the project_role_jump_account

    The project_role account is the role which projects will utilize in various AWS accounts, and the role only has permissions
    to AWS resources which begin with the project-name - which the exception of S3 buckets.  Because S3 buckets are globally scoped, the
    S3 bucket should be named environment-abbreviation, dash, project-name.

    Permissions are created with both upper and lower case.

    Utilize the aws-resources parameter to pass-in which resources the project will need access to.


Running From Command-Line

    To create a project jump account role:

```console
    role-creator upsert --project-name test --environment-abbreviation dv --aws-account-number 1234567890 --template-type project_role_jump_account --region us-east-1 --aws-profile will  --bucket cf-templates-987654
```

    To create a normal role for a project:

```console
    role-creator upsert --project-name test --environment-abbreviation dv --aws-account-number 12345678 --template-type project_role --region us-east-1 --aws-profile will --aws-resources ec2,cloudformation,s3,ecs,support,events,kms,waf,sns,states,iam,elasticloadbalancing,cloudwatch,cloudfront,elasticbeanstalk,ecr,autoscaling,dynamodb,sqs,acm,route53,codebuild,codepipeline,ssm,batch,apigateway,logs,elasticmapreduce --bucket cf-templates-987654
```
    NOTE: When you run from the command-line, and template.json file will automatically be created for future use
    NOTE: Project name and environment abbreviation are capitalized automatically for consistency

Running from and Ini File

Example Ini file

    [environment]
    template=template.json
    bucket = cf-templates
    template_type = project_role
    region = us-east-1
    stack_name = iam-role
    profile = me

    [tags]
    DeployedBy = me

    [parameters]
    UppercaseAwsEnvironmentPrefix = UT
    LowercaseAwsEnvironmentPrefix = ut
    AccountNumber = 123456789
    UppercaseProjectName = my-role
    LowercaseProjectName = my-role
    Resources = ec2,cloudformation,s3,ecs,support,events,kms,waf,sns,states,iam,elasticloadbalancing,cloudwatch,cloudfront,elasticbeanstalk,ecr,autoscaling,dynamodb,sqs,acm,route53,codebuild,codepipeline,ssm,batch,apigateway,logs,elasticmapreduce

    [meta-parameters]
    RoleName = my-role


Demonstration

<p><a target="_blank" rel="noopener noreferrer" href="https://github.com/rubelw/aws_role_creator/blob/master/images/demo.gif"><img src="https://github.com/rubelw/aws_role_creator/raw/master/images/demo.gif" alt="AWS role creator tutorial" style="max-width:100%;"></a></p>



Example of a Jump Account Role which allows the assumption of a role in another account


```console

{
    "Parameters": {
        "AccountNumber": {
            "Description": "AWS Account Number",
            "Type": "String"
        },
        "IAMNamespace": {
            "Default": "/",
            "Description": "Namespace for IAM users, policies, etc.",
            "Type": "String"
        },
        "LowercaseAwsEnvironmentPrefix": {
            "Description": "Lowercase abbreviation for AWS account (i.e. dev,qa,prod)",
            "Type": "String"
        },
        "LowercaseProjectName": {
            "Description": "Lowercase Project Name",
            "Type": "String"
        },
        "UppercaseAwsEnvironmentPrefix": {
            "Description": "Uppercase abbreviation for AWS account (i.e. DEV,QA,PROD)",
            "Type": "String"
        },
        "UppercaseProjectName": {
            "Description": "Uppercase Project Name",
            "Type": "String"
        }
    },
    "Resources": {
        "Group": {
            "Properties": {
                "GroupName": {
                    "Fn::Join": [
                        "-",
                        [
                            {
                                "Ref": "UppercaseAwsEnvironmentPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectName"
                            }
                        ]
                    ]
                }
            },
            "Type": "AWS::IAM::Group"
        },
        "ManagedPolicy": {
            "Properties": {
                "Description": {
                    "Fn::Join": [
                        "-",
                        [
                            {
                                "Ref": "UppercaseAwsEnvironmentPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectName"
                            },
                            "project"
                        ]
                    ]
                },
                "ManagedPolicyName": {
                    "Fn::Join": [
                        "-",
                        [
                            {
                                "Ref": "UppercaseAwsEnvironmentPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectName"
                            }
                        ]
                    ]
                },
                "Path": {
                    "Ref": "IAMNamespace"
                },
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Action": [
                                "sts:AssumeRole"
                            ],
                            "Effect": "Allow",
                            "Resource": [
                                "arn:aws:sts::1234567890:role/DV-TEST"
                            ],
                            "Sid": "StsAccess"
                        }
                    ],
                    "Version": "2012-10-17"
                }
            },
            "Type": "AWS::IAM::ManagedPolicy"
        }
    }
}
```


Example of the Role Created

```console
{
	"Parameters": {
		"AccountNumber": {
			"Description": "AWS Account Number",
			"Type": "String"
		},
		"IAMNamespace": {
			"Default": "/",
			"Description": "Namespace for IAM users, policies, etc.",
			"Type": "String"
		},
		"LowercaseAwsEnvironmentPrefix": {
			"Description": "Lowercase abbreviation for AWS account (i.e. dev,qa,prod)",
			"Type": "String"
		},
		"LowercaseProjectName": {
			"Description": "Lowercase Project Name",
			"Type": "String"
		},
		"UppercaseAwsEnvironmentPrefix": {
			"Description": "Uppercase abbreviation for AWS account (i.e. DEV,QA,PROD)",
			"Type": "String"
		},
		"UppercaseProjectName": {
			"Description": "Uppercase Project Name",
			"Type": "String"
		}
	},
	"Resources": {
		"IamGroup": {
			"Properties": {
				"GroupName": {
					"Fn::Join": [
						"-", [{
								"Ref": "UppercaseAwsEnvironmentPrefix"
							},
							{
								"Ref": "UppercaseProjectName"
							}
						]
					]
				},
				"Path": {
					"Ref": "IAMNamespace"
				}
			},
			"Type": "AWS::IAM::Group"
		},
		"ManagedPolicy": {
			"Properties": {
				"Description": {
					"Fn::Join": [
						"-", [{
								"Ref": "UppercaseAwsEnvironmentPrefix"
							},
							{
								"Ref": "UppercaseProjectName"
							},
							"project"
						]
					]
				},
				"Groups": [{
					"Fn::Join": [
						"-", [{
								"Ref": "UppercaseAwsEnvironmentPrefix"
							},
							{
								"Ref": "UppercaseProjectName"
							}
						]
					]
				}],
				"ManagedPolicyName": {
					"Fn::Join": [
						"-", [{
								"Ref": "UppercaseAwsEnvironmentPrefix"
							},
							{
								"Ref": "UppercaseProjectName"
							}
						]
					]
				},
				"Path": {
					"Ref": "IAMNamespace"
				},
				"PolicyDocument": {
					"Ref": {
						"Id": "Account-Permissions",
						"Statement": [{
								"Action": [
									"ec2:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:ec2:us-east-1:1234567890:TEST*",
									"arn:aws:ec2:us-east-1:1234567890:test*"
								],
								"Sid": "Ec2Access"
							},
							{
								"Action": [
									"cloudformation:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:cloudformation:us-east-1:1234567890:TEST*",
									"arn:aws:cloudformation:us-east-1:1234567890:test*"
								],
								"Sid": "CloudformationAccess"
							},
							{
								"Action": [
									"s3:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:s3:::DV-TEST/*",
									"arn:aws:s3:::DV-TEST*",
									"arn:aws:s3:::DV-test/*",
									"arn:aws:s3:::DV-test*"
								],
								"Sid": "S3Access"
							},
							{
								"Action": [
									"ecs:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:ecs:us-east-1:1234567890:TEST*",
									"arn:aws:ecs:us-east-1:1234567890:test*"
								],
								"Sid": "ECSAccess"
							},
							{
								"Action": [
									"support:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:support:us-east-1:1234567890:TEST*",
									"arn:aws:support:us-east-1:1234567890:test*"
								],
								"Sid": "SupportAccess"
							},
							{
								"Action": [
									"events:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:events:us-east-1:1234567890:TEST*",
									"arn:aws:events:us-east-1:1234567890:test*"
								],
								"Sid": "EventsAccess"
							},
							{
								"Action": [
									"kms:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:kms:us-east-1:1234567890:TEST*",
									"arn:aws:kms:us-east-1:1234567890:test*"
								],
								"Sid": "KmsAccess"
							},
							{
								"Action": [
									"waf:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:waf:us-east-1:1234567890:TEST*",
									"arn:aws:waf:us-east-1:1234567890:test*"
								],
								"Sid": "WafAccess"
							},
							{
								"Action": [
									"sns:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:sns:us-east-1:1234567890:TEST*",
									"arn:aws:sns:us-east-1:1234567890:test*"
								],
								"Sid": "SnsAccess"
							},
							{
								"Action": [
									"states:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:states:us-east-1:1234567890:TEST*",
									"arn:aws:states:us-east-1:1234567890:test*"
								],
								"Sid": "StatesAccess"
							},
							{
								"Action": [
									"iam:Get*",
									"iam:List*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:iam::1234567890:TEST*",
									"arn:aws:iam::1234567890:test*"
								],
								"Sid": "IamAccess"
							},
							{
								"Action": [
									"elasticloadbalancing:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:elasticloadbalancing:us-east-1:1234567890:TEST*",
									"arn:aws:elasticloadbalancing:us-east-1:1234567890:test*"
								],
								"Sid": "ElasticloadbalancingAccess"
							},
							{
								"Action": [
									"cloudwatch:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:cloudwatch:us-east-1:1234567890:TEST*",
									"arn:aws:cloudwatch:us-east-1:1234567890:test*"
								],
								"Sid": "CloudwatchAccess"
							},
							{
								"Action": [
									"cloudfront:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:cloudfront:us-east-1:1234567890:TEST*",
									"arn:aws:cloudfront:us-east-1:1234567890:test*"
								],
								"Sid": "CloudfrontAccess"
							},
							{
								"Action": [
									"elasticbeanstalk:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:elasticbeanstalk:us-east-1:1234567890:TEST*",
									"arn:aws:elasticbeanstalk:us-east-1:1234567890:test*"
								],
								"Sid": "ElasticbeanstalkAccess"
							},
							{
								"Action": [
									"ecr:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:ecr:us-east-1:1234567890:TEST*",
									"arn:aws:ecr:us-east-1:1234567890:test*"
								],
								"Sid": "EcrAccess"
							},
							{
								"Action": [
									"autoscaling:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:autoscaling:us-east-1:1234567890:TEST*",
									"arn:aws:autoscaling:us-east-1:1234567890:test*"
								],
								"Sid": "AutoscalingAccess"
							},
							{
								"Action": [
									"autoscaling:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:dynamodb:us-east-1:1234567890:TEST*",
									"arn:aws:dynamodb:us-east-1:1234567890:test*"
								],
								"Sid": "DynamodbAccess"
							},
							{
								"Action": [
									"sqs:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:sqs:us-east-1:1234567890:TEST*",
									"arn:aws:sqs:us-east-1:1234567890:test*"
								],
								"Sid": "SqsAccess"
							},
							{
								"Action": [
									"acm:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:acm:us-east-1:1234567890:TEST*",
									"arn:aws:acm:us-east-1:1234567890:test*"
								],
								"Sid": "AcmAccess"
							},
							{
								"Action": [
									"route53:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:route53:us-east-1:1234567890:TEST*",
									"arn:aws:route53:us-east-1:1234567890:test*"
								],
								"Sid": "Route53Access"
							},
							{
								"Action": [
									"codebuild:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:codebuild:us-east-1:1234567890:TEST*",
									"arn:aws:codebuild:us-east-1:1234567890:test*"
								],
								"Sid": "CodebuildAccess"
							},
							{
								"Action": [
									"codepipeline:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:codepipeline:us-east-1:1234567890:TEST*",
									"arn:aws:codepipeline:us-east-1:1234567890:test*"
								],
								"Sid": "CodepipelineAccess"
							},
							{
								"Action": [
									"ssm:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:ssm:us-east-1:1234567890:TEST*",
									"arn:aws:ssm:us-east-1:1234567890:test*"
								],
								"Sid": "SsmAccess"
							},
							{
								"Action": [
									"batch:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:batch:us-east-1:1234567890:TEST*",
									"arn:aws:batch:us-east-1:1234567890:test*"
								],
								"Sid": "BatchAccess"
							},
							{
								"Action": [
									"apigateway:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:apigateway:us-east-1:1234567890:TEST*",
									"arn:aws:apigateway:us-east-1:1234567890:test*"
								],
								"Sid": "ApigatewayAccess"
							},
							{
								"Action": [
									"logs:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:logs:us-east-1:1234567890:TEST*",
									"arn:aws:logs:us-east-1:1234567890:test*"
								],
								"Sid": "LogsAccess"
							},
							{
								"Action": [
									"elasticmapreduce:*"
								],
								"Effect": "Allow",
								"Resource": [
									"arn:aws:elasticmapreduce:us-east-1:1234567890:TEST*",
									"arn:aws:elasticmapreduce:us-east-1:1234567890:test*"
								],
								"Sid": "ElasticmapreduceAccess"
							}
						],
						"Version": "2012-10-17"
					}
				}
			},
			"Type": "AWS::IAM::ManagedPolicy"
		}
	}
}
```
