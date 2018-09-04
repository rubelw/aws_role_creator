from __future__ import absolute_import, division, print_function
import logging
import inspect
import os
import sys
import json
import traceback
import boto3
from stackility import CloudStackUtility
from tempfile import NamedTemporaryFile
from configparser import RawConfigParser
from stackility import StackTool


try:
    POLL_INTERVAL = os.environ.get('CSU_POLL_INTERVAL', 30)
except:
    POLL_INTERVAL = 30

def lineno():
    """Returns the current line number in our program."""
    return str(' - PipelineCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


class PipelineCreator:
    """
    Creates an AWS Codepipeline
    """

    def __init__(self, config_block, debug, project_name):
        """
        Initialize PipelineCreator
        :param config_block:
        """


        self.debug = False
        self.project_name = None

        if debug:
            self.debug = debug

        if project_name:
            self.project_name = project_name
        else:
            print('Need to have metadata parameters with project name')
            sys.exit(1)

        if config_block:
            self._config = config_block
        else:
            logging.error('config block was garbage')
            raise SystemError

        if 'template' in config_block:
            if debug:
                print('template provided in config block')

            if not self.validate_template():
                print('Template not validated')
                sys.exit(1)
        else:
            config_block['environment']['template'] = self.get_template()


        self.stack_driver = CloudStackUtility(config_block)


    def create(self):
        """
        Create a pipeline
        :return: rendered results
        """

        if self.debug:
            print('##################################')
            print('PipelineCreator - create'+lineno())
            print('##################################')

        poll_stack = not self.stack_driver._config.get('no_poll', False)

        print('## poll stack')
        if self.stack_driver.upsert():
            logging.info('stack create/update was started successfully.')

            if poll_stack:
                print('poll stack')
                if self.stack_driver.poll_stack():
                    logging.info('stack create/update was finished successfully.')
                    try:
                        profile = self.stack_driver._config.get('environment', {}).get('profile')
                        if profile:
                            boto3_session = boto3.session.Session(profile_name=profile)
                        else:
                            boto3_session = boto3.session.Session()

                        region = self.stack_driver._config['environment']['region']
                        stack_name = self.stack_driver._config['environment']['stack_name']

                        cf_client = self.stack_driver.get_cloud_formation_client()

                        if not cf_client:
                            cf_client = boto3_session.client('cloudformation', region_name=region)

                        print('calling stacktool')
                        stack_tool = stack_tool = StackTool(
                            stack_name,
                            region,
                            cf_client
                        )
                        stack_tool.print_stack_info()
                    except Exception as wtf:
                        logging.warning('there was a problems printing stack info: {}'.format(wtf))

                    sys.exit(0)
                else:
                    logging.error('stack create/update was did not go well.')
                    sys.exit(1)
        else:
            logging.error('start of stack create/update did not go well.')
            sys.exit(1)


    def find_myself(self):
        """
        Find myself
        Args:
            None
        Returns:
           An Amazon region
        """
        s = boto3.session.Session()
        return s.region_name

    def read_config_info(self, ini_file):
        """
        Read the INI file
        Args:
            ini_file - path to the file
        Returns:
            A dictionary of stuff from the INI file
        Exits:
            1 - if problems are encountered
        """
        try:
            config = RawConfigParser()
            config.optionxform = lambda option: option
            config.read(ini_file)
            the_stuff = {}
            for section in config.sections():
                the_stuff[section] = {}
                for option in config.options(section):
                    the_stuff[section][option] = config.get(section, option)

            return the_stuff
        except Exception as wtf:
            logging.error('Exception caught in read_config_info(): {}'.format(wtf))
            traceback.print_exc(file=sys.stdout)
            return sys.exit(1)


    def validate_template(self):

        datastore = json.load(f)

        with open(f.name, 'r') as file:
            template = json.loads(self.config_block['template'])


        if 'Parameters' in template:

            for parameter in template['parameters']:
                if parameter not in ["Project", "ProjectDescription", "DeploymentBucketName", "Image", "RepositoryName", "RepositoryBranchName", "BuildServiceRole", "Subnets", "SecurityGroups", "VpcId", "BuildProjectName", "EnvironmentCode", "BuildspecFile"]:
                    print('Parameter: '+str(parameter)+ ' is not in the template.  Make sure the template matches the readme')
                    sys.exit(1)
        else:
            print('Parameter must be in template')
            sys.exit(1)

        if 'Resources' in template:

            for resource in template['Resources']:
                if resource not in ["LogGroup", "CodeBuildProject", "Pipeline"]:
                    print('Resource: '+str(resource)+ ' is not in the template.  Make sure the template matches the readme')
                    sys.exit(1)
        else:
            print('Resource must be in template')
            sys.exit(1)

        return True

    def get_template(self):

        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "CodePipeline for "+str(self.project_name),
            "Parameters": {
                "Project": {
                    "Description": "The project code which owns this stack",
                    "Type": "String"
                },
                "ProjectDescription": {
                    "Description": "project description",
                    "Type": "String"
                },
                "DeploymentBucketName": {
                    "Description": "Logging bucket",
                    "Type": "String"
                },
                "Image": {
                    "Description": "Docker image",
                    "Type": "String"
                },
                "RepositoryName": {
                    "Description": "CodeCommit Repository Name",
                    "Type": "String"
                },
                "RepositoryBranchName": {
                    "Description": "CodeCommit Repository Branch Name",
                    "Type": "String"
                },
                "BuildServiceRole": {
                    "Description": "Code pipeline build service role",
                    "Type": "String"
                },
                "Subnets": {
                    "Type": "CommaDelimitedList"
                },
                "SecurityGroups": {
                    "Type": "CommaDelimitedList"
                },
                "VpcId": {
                    "Type": "String"
                },
                "BuildProjectName": {
                    "Type": "String"
                },
                "EnvironmentCode": {
                    "Type": "String"
                },
                "BuildspecFile": {
                    "Type": "String"
                }
            },
            "Resources": {

                "LogGroup": {
                    "Type": "AWS::Logs::LogGroup",
                    "DependsOn": "CodeBuildProject",
                    "Properties": {
                        "LogGroupName": {"Fn::Join": ["", ["/aws/codebuild/", {"Ref": "BuildProjectName"}]]},
                        "RetentionInDays": 90
                    }
                },

                "CodeBuildProject": {
                    "Type": "AWS::CodeBuild::Project",
                    "Properties": {
                        "Name": {"Ref": "BuildProjectName"},
                        "Description": {"Ref": "ProjectDescription"},
                        "ServiceRole": {"Ref": "BuildServiceRole"},
                        "Artifacts": {
                            "Type": "CODEPIPELINE"
                        },
                        "VpcConfig": {
                            "VpcId": {"Ref": "VpcId"},
                            "Subnets": {"Ref": "Subnets"},
                            "SecurityGroupIds": {"Ref": "SecurityGroups"}
                        },
                        "Environment": {
                            "Type": "linuxContainer",
                            "ComputeType": "BUILD_GENERAL1_SMALL",
                            "Image": {"Ref": "Image"},
                            "EnvironmentVariables": [
                                {
                                    "Name": "EnvCode",
                                    "Value": {
                                        "Ref": "EnvironmentCode"
                                    }
                                }
                            ]
                        },
                        "Source": {
                            "BuildSpec": {"Ref": "BuildspecFile"},
                            "Type": "CODEPIPELINE"
                        },
                        "TimeoutInMinutes": 60,
                        "Tags": [
                            {
                                "Key": "Name",
                                "Value": {
                                    "Fn::Join": [
                                        "-",
                                        [
                                            {
                                                "Ref": "AWS::StackName"
                                            }
                                        ]
                                    ]
                                }
                            }

                        ]
                    }
                },
                "Pipeline": {
                    "Type": "AWS::CodePipeline::Pipeline",
                    "Properties": {
                        "RoleArn": {"Ref": "BuildServiceRole"},
                        "ArtifactStore": {
                            "Type": "S3",
                            "Location": {"Ref": "DeploymentBucketName"}
                        },
                        "Stages": [
                            {
                                "Name": "Source",
                                "Actions": [
                                    {
                                        "Name": "SourceAction",
                                        "ActionTypeId": {
                                            "Category": "Source",
                                            "Owner": "AWS",
                                            "Version": "1",
                                            "Provider": "CodeCommit"
                                        },
                                        "OutputArtifacts": [
                                            {
                                                "Name": "CodePipelineSourceOutputArtifact"
                                            }
                                        ],
                                        "Configuration": {
                                            "BranchName": {"Ref": "RepositoryBranchName"},
                                            "RepositoryName": {"Ref": "RepositoryName"}
                                        },
                                        "RunOrder": 1
                                    }
                                ]
                            },
                            {
                                "Name": "Build",
                                "Actions": [{
                                    "Name": "BuildAction",
                                    "InputArtifacts": [{
                                        "Name": "CodePipelineSourceOutputArtifact"
                                    }],
                                    "ActionTypeId": {
                                        "Category": "Build",
                                        "Owner": "AWS",
                                        "Version": 1,
                                        "Provider": "CodeBuild"
                                    },
                                    "Configuration": {
                                        "ProjectName": {
                                            "Ref": "CodeBuildProject"
                                        }
                                    },
                                    "OutputArtifacts": [{
                                        "Name": "CodePipelineBuildOutputArtifact"
                                    }],
                                    "RunOrder": 1
                                }]
                            }
                        ]
                    }
                }
            }
        }


        f = NamedTemporaryFile(delete=False)

        # Save original name (the "name" actually is the absolute path)
        original_path = f.name

        if self.debug:
            print('original_path: '+str(original_path))
            print('path: '+str(os.path.dirname(original_path)))
        # Change the file name to something
        f.name = str(os.path.dirname(original_path))+'/myfilename.json'

        with open(f.name, 'w') as file:
            file.write(json.dumps(template))

        return f.name