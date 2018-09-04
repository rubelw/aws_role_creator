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
        "IamGroup": {
            "Type": "AWS::IAM::Group",
            "Properties": {
                "Path": "/",
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
            }
        },
        "ManagedPolicy": {
            "Type": "AWS::IAM::ManagedPolicy",
            "DependsOn": "IamGroup",
            "Properties": {
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
                "Groups": [
                    {
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
                ],
                "Description": {
                    "Fn::Join": [
                        "",
                        [
                            "Policy for ",
                            {
                                "Ref": "UppercaseAwsEnvironmentPrefix"
                            },
                            {
                                "Ref": "UppercaseProjectName"
                            },
                            " project"
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
                                "sts:AssumeRole"
                            ],
                            "Resource": [
                                {
                                    "Fn::Join": [
                                        "",
                                        [
                                            "arn:aws:iam::",
                                            {
                                                "Ref": "AccountNumber"
                                            },
                                            ":role/",
                                            {
                                                "Ref": "UppercaseAwsEnvironmentPrefix"
                                            },
                                            "-",
                                            {
                                                "Ref": "UppercaseProjectName"
                                            }
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
                                "s3:AbortMultipartUpload",
                                "s3:GetAccelerateConfiguration",
                                "s3:GetBucketAcl",
                                "s3:GetBucketCORS",
                                "s3:GetBucketLocation",
                                "s3:GetBucketLogging",
                                "s3:GetBucketNotification",
                                "s3:GetBucketPolicy",
                                "s3:GetBucketRequestPayment",
                                "s3:GetBucketTagging",
                                "s3:GetBucketVersioning",
                                "s3:GetBucketWebsite",
                                "s3:GetEncryptionConfiguration",
                                "s3:GetLifecycleConfiguration",
                                "s3:GetObject",
                                "s3:GetObjectAcl",
                                "s3:GetObjectTorrent",
                                "s3:GetObjectVersion",
                                "s3:GetObjectVersionAcl",
                                "s3:GetObjectVersionTorrent",
                                "s3:GetReplicationConfiguration",
                                "s3:ListAllMyBuckets",
                                "s3:ListBucket",
                                "s3:ListBucketMultipartUploads",
                                "s3:ListBucketVersions",
                                "s3:ListMultipartUploadParts",
                                "s3:PutBucketTagging",
                                "s3:PutBucketVersioning",
                                "s3:PutLifecycleConfiguration",
                                "s3:PutReplicationConfiguration",
                                "s3:PutObject"
                            ],
                            "Resource": [
                                { "Fn::Join" : [ "", [
                                    "arn:aws:s3:::",
                                    {"Ref":"LowercaseAwsEnvironmentPrefix"},
                                    "-",
                                    {"Ref":"LowercaseProjectName"}

                                ] ] },
                                { "Fn::Join" : [ "", [
                                    "arn:aws:s3:::",
                                    {"Ref":"LowercaseAwsEnvironmentPrefix"},
                                    "-",
                                    {"Ref":"LowercaseProjectName"},
                                    "/*"

                                ] ] }
                            ]
                        }
                    ]
                }
            }
        }
    }
}