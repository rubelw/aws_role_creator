{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "IAM Roles and policies for parp-m",
    "Parameters": {
        "IAMNamespace": {
            "Description": "Namespace for IAM users, policies, etc.",
            "Type": "String",
            "Default": "/"
        },
        "UppercaseAwsEnvironmentPrefix": {
            "Description": "Account prefix",
            "Type": "String"
        },
        "LowercaseAwsEnvironmentPrefix": {
            "Description": "Account prefix",
            "Type": "String"
        },
        "AccountNumber": {
            "Description": "AWS Account number",
            "Type": "String"
        },
        "UppercaseProjectName": {
            "Type": "String"
        },
        "LowercaseProjectName": {
            "Type": "String"
        }
    },
    "Resources": {
        "ProfilePolicy": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": {
                    "Fn::Join": [
                        "-",
                        [
                            {
                                "Ref": "GroupPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectCode"
                            },
                            "Profile"
                        ]
                    ]
                },
                "Description": "Policy for {{project_name}} profile",
                "Path": {
                    "Ref": "IAMNamespace"
                },
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                         {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                            ],
                            "Resource": "*"
                        },
                        {
                            "Effect": "Allow",
                            "NotAction": [
                                "s3:CreateBucket",
                                "s3:DeleteBucket",
                                "s3:*BucketPolicy",
                                "s3:*BucketACL",
                                "s3:*BucketWebsite",
                                "s3:*BucketReplicationConfiguration"
                            ],
                            "Resource": [
                                { "Fn::Join" : [ "", [
                                    "arn:aws:s3:::",
                                    {"Ref":"LowercaseGroupPrefix"},
                                    "-",
                                    {"Ref":"LowercaseProjectCode"}

                                ] ] },
                                { "Fn::Join" : [ "", [
                                    "arn:aws:s3:::",
                                    {"Ref":"LowercaseGroupPrefix"},
                                    "-",
                                    {"Ref":"LowercaseProjectCode"},
                                    "/*"
                                ] ] }
                            ]
                        }
                    ]
                }
            }
        },
        "Policy": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": {
                    "Fn::Join": [
                        "-",
                        [
                            {
                                "Ref": "GroupPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectCode"
                            }
                        ]
                    ]
                },
                "Description": {
                    "Fn::Join": [
                        "",
                        [
                            "Policy for ",
                            {
                                "Ref": "UppercaseProjectCode"
                            }
                        ]
                    ]
                },
                "Path": {
                    "Ref": "IAMNamespace"
                },
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "ssm:GetParameters",
                                "ssm:ListDocuments",
                                "ssm:ListDocumentsVersions",
                                "ssm:DescribeDocument",
                                "ssm:GetDocument",
                                "ssm:DescribeInstanceInformation",
                                "ssm:DescribeDocumentParameters",
                                "ssm:DescribeInstanceProperties",
                                "ssm:DescribeParameters",
                                "ssm:PutParameter",
                                "ssm:GetParameters",
                                "ssm:DeleteParameter"
                            ],
                            "Resource": [
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:ssm:us-east-1:",
                                            {
                                                "Ref": "AccountNumber"
                                            },
                                            ":parameter/",
                                            {
                                                "Ref": "LowercaseProjectCode"
                                            },
                                            "*"
                                        ]
                                    ]
                                }
                            ]
                        },
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": [
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:iam::*:role/",
                                            {
                                                "Ref": "GroupPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "UppercaseProjectCode"
                                            }
                                        ]
                                    ]
                                },
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:iam::*:role/",
                                            {
                                                "Ref": "GroupPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "UppercaseProjectCode"
                                            },
                                            "/*"
                                        ]
                                    ]
                                }
                            ]
                        },
                        {
                            "Effect": "Allow",
                            "NotAction": [
                                "s3:CreateBucket",
                                "s3:DeleteBucket",
                                "s3:GetBucketPolicy",
                                "s3:GetBucketACL",
                                "s3:GetBucketWebsite",
                                "s3:GetBucketReplicationConfiguration"
                            ],
                            "Resource": [
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:s3:::",
                                            {
                                                "Ref": "LowercaseGroupPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "LowercaseProjectCode"
                                            }
                                        ]
                                    ]
                                },
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:s3:::",
                                            {
                                                "Ref": "LowercaseGroupPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "LowercaseProjectCode"
                                            },
                                            "/*"
                                        ]
                                    ]
                                }
                            ]
                        },
                        {
                            "Action": "ecr:Get",
                            "Effect": "Allow",
                            "Resource": "*"
                        },
                        {
                            "Sid": "CFN",
                            "Action": "cloudformation:*",
                            "Effect": "Allow",
                            "Resource": [
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:cloudformation:us-east-1:",
                                            {
                                                "Ref": "AccountNumber"
                                            },
                                            ":stack/",
                                            {
                                                "Ref": "GroupPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "UppercaseProjectCode"
                                            },
                                            "*"
                                        ]
                                    ]
                                },
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:cloudformation:us-east-1:",
                                            {
                                                "Ref": "AccountNumber"
                                            },
                                            ":stack/",
                                            {
                                                "Ref": "LowercaseGroupPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "LowercaseProjectCode"
                                            },
                                            "*"
                                        ]
                                    ]
                                }
                            ],
                            "Condition": {
                                "ArnNotEquals": {
                                    "cloudformation:StackPolicyUrl": []
                                }
                            }
                        }


                    ]
                }
            }
        },
        "ProfileRole": {
            "DependsOn": "ProfilePolicy",
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {
                    "Fn::Join": [
                        "",
                        [
                            {
                                "Ref": "GroupPrefix"
                            },
                            "-",
                            {
                                "Ref": "UppercaseProjectCode"
                            },
                            "-Profile"
                        ]
                    ]
                },
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                          "Sid": "",
                          "Effect": "Allow",
                          "Principal": {
                            "AWS": "arn:aws:iam::118820389895:root",
                            "Service": [
                              "lambda.amazonaws.com",
                              "apigateway.amazonaws.com",
                              "events.amazonaws.com"
                            ]
                          },
                          "Action": "sts:AssumeRole"
                        }
                    ]
                },
                "ManagedPolicyArns": [
                    {
                        "Fn::Join": [
                            "",
                            [
                                "arn:aws:iam::",
                                {
                                    "Ref": "AccountNumber"
                                },
                                ":policy/",
                                {
                                    "Ref": "GroupPrefix"
                                },
                                "-",
                                {
                                    "Ref": "UppercaseProjectCode"
                                },
                                "-Profile"
                            ]
                        ]
                    },
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
                ],
                "Policies": [
                    {
                        "PolicyName": "IAM-AssumeOwnRole-20170619",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "Stmt1436198756000",
                                    "Effect": "Allow",
                                    "Action": [
                                        "sts:AssumeRole"
                                    ],
                                    "Resource": [
                                        "arn:aws:iam::118820389895:role/ut-io-codepipeline-permissions-AWSCodeDeployRole-1UZ947RDOP7T7"
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        },
        "Role": {
            "DependsOn": "Policy",
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {
                    "Fn::Join": [
                        "",
                        [
                            {
                                "Ref": "GroupPrefix"
                            },
                            "-",
                            {
                                "Ref": "UppercaseProjectCode"
                            }
                        ]
                    ]
                },
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": [
                                    "arn:aws:iam::118820389895:root"
                                ]
                            },
                            "Action": [
                                "sts:AssumeRole"
                            ]
                        }
                    ]
                },
                "ManagedPolicyArns": [
                    {
                        "Fn::Join": [
                            "",
                            [
                                "arn:aws:iam::",
                                {
                                    "Ref": "AccountNumber"
                                },
                                ":policy/",
                                {
                                    "Ref": "GroupPrefix"
                                },
                                "-",
                                {
                                    "Ref": "UppercaseProjectCode"
                                }
                            ]
                        ]
                    }
                ],
                "Policies": []
            }
        },
        "Profile": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {
                "Path": "/",
                "Roles": [
                    {
                        "Ref": "ProfileRole"
                    }
                ],
                "InstanceProfileName": {
                    "Fn::Join": [
                        "",
                        [
                            {
                                "Ref": "GroupPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectCode"
                            },
                            "Profile"
                        ]
                    ]
                }
            }
        }
    }
}