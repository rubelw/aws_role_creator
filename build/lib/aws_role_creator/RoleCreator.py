from __future__ import absolute_import, division, print_function
import logging
import inspect
import os
import sys
import json
import traceback
import jinja2
import boto3
import tempfile
from stackility import CloudStackUtility
from tempfile import NamedTemporaryFile
from configparser import RawConfigParser
from stackility import StackTool
from troposphere import Ref, Template, Parameter, Output, Join
from troposphere.iam import AccessKey, Group, LoginProfile, PolicyType, ManagedPolicy, Role

from awacs.aws import Action, Allow, PolicyDocument, Principal, Statement
from awacs.iam import ARN as IAM_ARN
from awacs.s3  import ARN as S3_ARN
from awacs.cloudformation  import ARN as CLOUDFORMATION_ARN
from awacs.ec2  import ARN as EC2_ARN
from awacs.ecs  import ARN as ECS_ARN
from awacs.support import ARN as SUPPORT_ARN
from awacs.events import ARN as EVENTS_ARN
from awacs.kms import ARN as KMS_ARN
from awacs.rds import ARN as RDS_ARN
from awacs.waf import ARN as WAF_ARN
from awacs.sns import ARN as SNS_ARN
from awacs.states import ARN as STATES_ARN
from awacs.elasticloadbalancing import ARN as ELASTICLOADBALANCING_ARN
from awacs.cloudwatch import ARN as CLOUDWATCH_ARN
from awacs.cloudfront import ARN as CLOUDFRONT_ARN
from awacs.elasticbeanstalk import ARN as ELASTICBEANSTALK_ARN
from awacs.ecr import ARN as ECR_ARN
from awacs.autoscaling import ARN as AUTOSCALING_ARN
from awacs.dynamodb import ARN as DYNAMODB_ARN
from awacs.sqs import ARN as SQS_ARN
from awacs.acm import ARN as ACM_ARN
from awacs.route53 import ARN as ROUTE53_ARN
from awacs.codebuild import ARN as CODEBUILD_ARN
from awacs.codepipeline import ARN as CODEPIPELINE_ARN
from awacs.ssm import ARN as SSM_ARN
from awacs.batch import ARN as BATCH_ARN
from awacs.logs import ARN as LOGS_ARN
from awacs.apigateway import ARN as APIGATEWAY_ARN
from awacs.elasticmapreduce import ARN as ELASTICMAPEDUCE_ARN
from awacs.sts import ARN as STS_ARN

try:
    POLL_INTERVAL = os.environ.get('CSU_POLL_INTERVAL', 30)
except:
    POLL_INTERVAL = 30

def lineno():
    """Returns the current line number in our program."""
    return str(' - RoleCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


class RoleCreator:
    """
    Creates an AWS Role
    """

    def __init__(self, config_block, debug, role_name):
        """
        Initialize RoleCreator
        :param config_block:
        """

        self.debug = False
        self.role_name = None
        self.template_type = None
        self.cwd = None

        if debug:
            self.debug = debug

        self.cwd = str(config_block['cwd'])

        if role_name:
            self.role_name = role_name
        else:
            print('Need to have metadata parameters with project name')
            sys.exit(1)

        if config_block:
            self._config = config_block
        else:
            logging.error('config block was garbage')
            raise SystemError

        if 'template' in self._config['environment'] and self._config['environment']['template']:
            if debug:
                print('template provided in config block')

            if not self.validate_template():
                print('Template not validated')
                sys.exit(1)
        else:
            if 'template_type' not in self._config['environment']:
                if debug:
                    print('a normal template passed-in')
            else:
                self.template_type = self._config['environment']['template_type']

                self._config['environment']['template'] = self.get_template()

        if debug:
            print('config: '+str(self._config))

        self.stack_driver = CloudStackUtility(self._config)


    def create(self):
        """
        Create a role
        :return: rendered results
        """

        if self.debug:
            print('##################################')
            print('RoleCreator - create'+lineno())
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


    def create_template(self):


        if self.template_type == 'project_role':

            template = Template()

            namespace_param = template.add_parameter(
                Parameter(
                    "IAMNamespace",
                    Description="Namespace for IAM users, policies, etc.",
                    Type="String",
                    Default="/"
                )
            )

            uppercase_env_prefix_param = template.add_parameter(
                Parameter(
                    "UppercaseAwsEnvironmentPrefix",
                    Description="Uppercase abbreviation for AWS account (i.e. DEV,QA,PROD)",
                    Type="String"
                )
            )

            lowercase_env_prefix_param = template.add_parameter(
                Parameter(
                    "LowercaseAwsEnvironmentPrefix",
                    Description="Lowercase abbreviation for AWS account (i.e. dev,qa,prod)",
                    Type="String"
                )
            )
            aws_account_number_param = template.add_parameter(
                Parameter(
                    "AccountNumber",
                    Description="AWS Account Number",
                    Type="String"
                )
            )
            uppercase_project_name_param = template.add_parameter(
                Parameter(
                    "UppercaseProjectName",
                    Description="Uppercase Project Name",
                    Type="String"
                )
            )
            lowercase_project_name_param = template.add_parameter(
                Parameter(
                    "LowercaseProjectName",
                    Description="Lowercase Project Name",
                    Type="String"
                )
            )

            pd = PolicyDocument(
                Version="2012-10-17",
                Id="Account-Permissions",
                Statement=self.create_policy_document()
            )

            iam_group = template.add_resource(
                Group(
                    'IamGroup',

                    #Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param)])
                    Path=Ref(namespace_param),
                    GroupName = Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param)])
                    #'ManagedPolicyArns': ([basestring], False),

                    #Policies'= ([Policy], False)
                )
            )

            iam_managed_policy = template.add_resource(
                ManagedPolicy(
                    "ManagedPolicy",
                    Description= Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param),'project']),
                    Groups= [Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param)])],
                    ManagedPolicyName= Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param)]),
                    Path= Ref(namespace_param),
                    PolicyDocument= pd

                )
            )

            if self.debug:
                print(template.to_json())

            with tempfile.NamedTemporaryFile(mode='w', suffix='.rdr', delete=False) as tmp:
                tmp.write(template.to_json())
            self._config.pop('meta-parameters', None)

            if (not os.path.exists(self.cwd + '/template.json') and not self._config['environment']['template']):

                with open(self.cwd + '/template.json', 'w') as file:
                    file.write(template.to_json())
                file.close()
            else:
                if self.debug:
                    print('Not creating template.json')

            return tmp.name

        elif  self.template_type == 'project_role_jump_account':

            self._config['parameters'].pop('Resources', None)

            template = Template()

            namespace_param = template.add_parameter(
                Parameter(
                    "IAMNamespace",
                    Description="Namespace for IAM users, policies, etc.",
                    Type="String",
                    Default="/"
                )
            )

            uppercase_env_prefix_param = template.add_parameter(
                Parameter(
                    "UppercaseAwsEnvironmentPrefix",
                    Description="Uppercase abbreviation for AWS account (i.e. DEV,QA,PROD)",
                    Type="String"
                )
            )

            lowercase_env_prefix_param = template.add_parameter(
                Parameter(
                    "LowercaseAwsEnvironmentPrefix",
                    Description="Lowercase abbreviation for AWS account (i.e. dev,qa,prod)",
                    Type="String"
                )
            )
            aws_account_number_param = template.add_parameter(
                Parameter(
                    "AccountNumber",
                    Description="AWS Account Number",
                    Type="String"
                )
            )
            uppercase_project_name_param = template.add_parameter(
                Parameter(
                    "UppercaseProjectName",
                    Description="Uppercase Project Name",
                    Type="String"
                )
            )
            lowercase_project_name_param = template.add_parameter(
                Parameter(
                    "LowercaseProjectName",
                    Description="Lowercase Project Name",
                    Type="String"
                )
            )

            pd = PolicyDocument(
                Version="2012-10-17",
                Statement=self.create_policy_document()
            )

            iam_policy = template.add_resource(
                ManagedPolicy(
                    'ManagedPolicy',
                    Description=Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param),'project']),
                    PolicyDocument=pd,
                    ManagedPolicyName=Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param)]),
                    Path=Ref(namespace_param)
                )
            )

            iam_group = template.add_resource(
                Group(
                    "Group",
                    GroupName= Join('-', [Ref(uppercase_env_prefix_param),Ref(uppercase_project_name_param)])
                )
            )
            if self.debug:
                print(template.to_json())


            with tempfile.NamedTemporaryFile(mode='w', suffix='.rdr', delete=False) as tmp:
                tmp.write(template.to_json())
            self._config.pop('meta-parameters', None)

            if (not os.path.exists(self.cwd + '/template.json') and not self._config['environment']['template']):

                with open(self.cwd + '/template.json', 'w') as file:
                    file.write(template.to_json())
                file.close()
            else:
                if self.debug:
                    print('Not creating template.json')

            if self.debug:
                print('template file is: '+str(tmp.name))
            return tmp.name

        else:
            print('incorrect template type')
            sys.exit(1)

    def create_policy_document(self):
        if self.template_type == 'project_role':

            if self.debug:
                print('template type is project_role')


            resources = self._config['parameters']['Resources'].split(',')
            resources_list = []

            for resource in resources:
                resources_list.append(str(resource.strip()))

            if self.debug:
                print('resources list: '+str(resources_list))

            statements = []
            for resource in resources_list:

                if resource == 'ec2':
                    statements.append(self.create_ec2_policy())
                elif resource == 's3':
                    statements.append(self.create_s3_policy())
                elif resource == 'cloudformation':
                    statements.append(self.create_cloudformation_policy())
                elif resource == 'ecs':
                    statements.append(self.create_ecs_policy())
                elif resource == 'support':
                    statements.append(self.create_support_policy())
                elif resource == 'events':
                    statements.append(self.create_events_policy())
                elif resource == 'kms':
                    statements.append(self.create_kms_policy())
                elif resource == 'rds':
                    statements.append(self.create_rds_policy())
                elif resource == 'waf':
                    statements.append(self.create_waf_policy())
                elif resource == 'sns':
                    statements.append(self.create_sns_policy())
                elif resource == 'states':
                    statements.append(self.create_states_policy())
                elif resource == 'iam':
                    statements.append(self.create_iam_policy())
                elif resource == 'elasticloadbalancing':
                    statements.append(self.create_elasticloadbalancing_policy())
                elif resource == 'cloudwatch':
                    statements.append(self.create_cloudwatch_policy())
                elif resource == 'cloudfront':
                    statements.append(self.create_cloudfront_policy())
                elif resource == 'elasticbeanstalk':
                    statements.append(self.create_elasticbeanstalk_policy())
                elif resource == 'ecr':
                    statements.append(self.create_ecr_policy())
                elif resource == 'autoscaling':
                    statements.append(self.create_autoscaling_policy())
                elif resource == 'dynamodb':
                    statements.append(self.create_dynamodb_policy())
                elif resource == 'sqs':
                    statements.append(self.create_sqs_policy())
                elif resource == 'acm':
                    statements.append(self.create_acm_policy())
                elif resource == 'route53':
                    statements.append(self.create_route53_policy())
                elif resource == 'codebuild':
                    statements.append(self.create_codebuild_policy())
                elif resource == 'codepipeline':
                    statements.append(self.create_codepipeline_policy())
                elif resource == 'ssm':
                    statements.append(self.create_ssm_policy())
                elif resource == 'batch':
                    statements.append(self.create_batch_policy())
                elif resource == 'logs':
                    statements.append(self.create_logs_policy())
                elif resource == 'apigateway':
                    statements.append(self.create_apigateway_policy())
                elif resource == 'elasticmapreduce':
                    statements.append(self.create_elasticmapreduce_policy())

            return statements

        elif  self.template_type == 'project_role_jump_account':
            if self.debug:
                print('template type is project_role_jump_account')

            account = self._config['parameters']['AccountNumber']


            if self.debug:
                print('account: ' + str(account))

            statements = []

            statements.append(self.create_sts_policy())
            return statements


    def create_sts_policy(self):
        action = Action(
            "sts",
            "AssumeRole"
        )
        sts_arn1 = STS_ARN(
            resource='role/'+str(self._config['parameters']['UppercaseAwsEnvironmentPrefix'])+ '-'+str(self._config['parameters']['UppercaseProjectName']),
            account=str(self._config['parameters']['AccountNumber'])
        )

        statement = Statement(
            Sid="StsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[sts_arn1]
        )

        return statement



    def create_elasticmapreduce_policy(self):
        action = Action(
            "elasticmapreduce",
            "*"
        )
        elasticmapreduce_arn1 = ELASTICMAPEDUCE_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        elasticmapreduce_arn2 = ELASTICMAPEDUCE_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="ElasticmapreduceAccess",
            Effect=Allow,
            Action=[action],
            Resource=[elasticmapreduce_arn1,elasticmapreduce_arn2]
        )

        return statement

    def create_apigateway_policy(self):
        action = Action(
            "apigateway",
            "*"
        )
        apigateway_arn1 = APIGATEWAY_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        apigateway_arn2 = APIGATEWAY_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="ApigatewayAccess",
            Effect=Allow,
            Action=[action],
            Resource=[apigateway_arn1,apigateway_arn2]
        )

        return statement


    def create_logs_policy(self):
        action = Action(
            "logs",
            "*"
        )
        logs_arn1 = LOGS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        logs_arn2 = LOGS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="LogsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[logs_arn1,logs_arn2]
        )

        return statement

    def create_batch_policy(self):
        action = Action(
            "batch",
            "*"
        )
        batch_arn1 = BATCH_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        batch_arn2 = BATCH_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="BatchAccess",
            Effect=Allow,
            Action=[action],
            Resource=[batch_arn1,batch_arn2]
        )

        return statement

    def create_ssm_policy(self):
        action = Action(
            "ssm",
            "*"
        )
        ssm_arn1 = SSM_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        ssm_arn2 = SSM_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="SsmAccess",
            Effect=Allow,
            Action=[action],
            Resource=[ssm_arn1,ssm_arn2]
        )

        return statement


    def create_codebuild_policy(self):
        action = Action(
            "codebuild",
            "*"
        )
        codebuild_arn1 = CODEBUILD_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        codebuild_arn2 = CODEBUILD_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="CodebuildAccess",
            Effect=Allow,
            Action=[action],
            Resource=[codebuild_arn1,codebuild_arn2]
        )

        return statement

    def create_codepipeline_policy(self):
        action = Action(
            "codepipeline",
            "*"
        )
        codepipeline_arn1 = CODEPIPELINE_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        codepipeline_arn2 = CODEPIPELINE_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="CodepipelineAccess",
            Effect=Allow,
            Action=[action],
            Resource=[codepipeline_arn1,codepipeline_arn2]
        )

        return statement

    def create_acm_policy(self):
        action = Action(
            "acm",
            "*"
        )
        acm_arn1 = ACM_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        acm_arn2 = ACM_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="AcmAccess",
            Effect=Allow,
            Action=[action],
            Resource=[acm_arn1,acm_arn2]
        )

        return statement

    def create_route53_policy(self):
        action = Action(
            "route53",
            "*"
        )
        route53_arn1 = ROUTE53_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*'
        )
        route53_arn2 = ROUTE53_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*'
        )
        statement = Statement(
            Sid="Route53Access",
            Effect=Allow,
            Action=[action],
            Resource=[route53_arn1,route53_arn2]
        )

        return statement

    def create_sqs_policy(self):
        action = Action(
            "sqs",
            "*"
        )
        sqs_arn1 = SQS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        sqs_arn2 = SQS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="SqsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[sqs_arn1,sqs_arn2]
        )

        return statement

    def create_dynamodb_policy(self):
        action = Action(
            "autoscaling",
            "*"
        )
        dynamodb_arn1 = DYNAMODB_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        dynamodb_arn2 = DYNAMODB_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="DynamodbAccess",
            Effect=Allow,
            Action=[action],
            Resource=[dynamodb_arn1,dynamodb_arn2]
        )

        return statement

    def create_autoscaling_policy(self):
        action = Action(
            "autoscaling",
            "*"
        )
        autoscaling_arn1 = AUTOSCALING_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        autoscaling_arn2 = AUTOSCALING_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="AutoscalingAccess",
            Effect=Allow,
            Action=[action],
            Resource=[autoscaling_arn1,autoscaling_arn2]
        )

        return statement

    def create_ecr_policy(self):
        action = Action(
            "ecr",
            "*"
        )
        ecr_arn1 = ECR_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        ecr_arn2 = ECR_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="EcrAccess",
            Effect=Allow,
            Action=[action],
            Resource=[ecr_arn1,ecr_arn2]
        )

        return statement


    def create_elasticbeanstalk_policy(self):
        action = Action(
            "elasticbeanstalk",
            "*"
        )
        elasticbeanstalk_arn1 = ELASTICBEANSTALK_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        elasticbeanstalk_arn2 = ELASTICBEANSTALK_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="ElasticbeanstalkAccess",
            Effect=Allow,
            Action=[action],
            Resource=[elasticbeanstalk_arn1,elasticbeanstalk_arn2]
        )

        return statement

    def create_cloudfront_policy(self):
        action = Action(
            "cloudfront",
            "*"
        )
        cloudfront_arn1 = CLOUDFRONT_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        cloudfront_arn2 = CLOUDFRONT_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="CloudfrontAccess",
            Effect=Allow,
            Action=[action],
            Resource=[cloudfront_arn1,cloudfront_arn2]
        )

        return statement

    def create_cloudwatch_policy(self):
        action = Action(
            "cloudwatch",
            "*"
        )
        cloudwatch_arn1 = CLOUDWATCH_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        cloudwatch_arn2 = CLOUDWATCH_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="CloudwatchAccess",
            Effect=Allow,
            Action=[action],
            Resource=[cloudwatch_arn1,cloudwatch_arn2]
        )

        return statement

    def create_elasticloadbalancing_policy(self):
        action = Action(
            "elasticloadbalancing",
            "*"
        )
        elasticloadbalancing_arn1 = ELASTICLOADBALANCING_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        elasticloadbalancing_arn2 = ELASTICLOADBALANCING_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="ElasticloadbalancingAccess",
            Effect=Allow,
            Action=[action],
            Resource=[elasticloadbalancing_arn1,elasticloadbalancing_arn2]
        )

        return statement

    def create_states_policy(self):
        action = Action(
            "states",
            "*"
        )
        states_arn1 = STATES_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        states_arn2 = STATES_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="StatesAccess",
            Effect=Allow,
            Action=[action],
            Resource=[states_arn1,states_arn2]
        )

        return statement

    def create_sns_policy(self):
        action = Action(
            "sns",
            "*"
        )
        sns_arn1 = SNS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        sns_arn2 = SNS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="SnsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[sns_arn1,sns_arn2]
        )

        return statement

    def create_iam_policy(self):
        get_action = Action(
            "iam",
            "Get*"
        )
        list_action = Action(
            "iam",
            "List*"
        )
        iam_arn1 = IAM_ARN(
            resource = 'role/'+self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        iam_arn2 = IAM_ARN(
            resource = 'role/'+self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="IamAccess",
            Effect=Allow,
            Action=[get_action,list_action],
            Resource=[iam_arn1, iam_arn2]
        )

        return statement

    def create_waf_policy(self):
        action = Action(
            "waf",
            "*"
        )
        waf_arn1 = WAF_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        waf_arn2 = WAF_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="WafAccess",
            Effect=Allow,
            Action=[action],
            Resource=[waf_arn1, waf_arn2]
        )

        return statement

    def create_rds_policy(self):
        action = Action(
            "rds",
            "*"
        )
        rds_arn1 = RDS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        rds_arn2 = RDS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )

        statement = Statement(
            Sid="RdsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[rds_arn1, rds_arn2]
        )

        return statement

    def create_kms_policy(self):
        action = Action(
            "kms",
            "*"
        )
        kms_arn1 = KMS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )

        kms_arn2 = KMS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="KmsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[kms_arn1, kms_arn2]
        )

        return statement

    def create_events_policy(self):
        action = Action(
            "events",
            "*"
        )
        events_arn1 = EVENTS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        events_arn2 = EVENTS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )

        statement = Statement(
            Sid="EventsAccess",
            Effect=Allow,
            Action=[action],
            Resource=[events_arn1, events_arn2]
        )

        return statement

    def create_support_policy(self):
        action = Action(
            "support",
            "*"
        )
        support_arn1 = SUPPORT_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        support_arn2 = SUPPORT_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="SupportAccess",
            Effect=Allow,
            Action=[action],
            Resource=[support_arn1, support_arn2]
        )

        return statement


    def create_ecs_policy(self):
        action = Action(
            "ecs",
            "*"
        )
        ecs_arn1 = ECS_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        ecs_arn2 = ECS_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="ECSAccess",
            Effect=Allow,
            Action=[action],
            Resource=[ecs_arn1, ecs_arn2]
        )

        return statement



    def create_cloudformation_policy(self):
        action = Action(
            "cloudformation",
            "*"
        )
        cf_arn1 = CLOUDFORMATION_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        cf_arn2 = CLOUDFORMATION_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])

        )
        statement = Statement(
            Sid="CloudformationAccess",
            Effect=Allow,
            Action=[action],
            Resource=[cf_arn1,cf_arn2]
        )

        return statement

    def create_ec2_policy(self):

        action = Action(
            "ec2",
            "*"
        )

        ec2_arn1 = EC2_ARN(
            resource = self._config['parameters']['UppercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        ec2_arn2 = EC2_ARN(
            resource = self._config['parameters']['LowercaseProjectName']+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        statement = Statement(
            Sid="Ec2Access",
            Effect=Allow,
            Action=[action],
            Resource=[ec2_arn1, ec2_arn2]
        )


        return statement

    def create_s3_policy(self):

        principal = Principal(
            "AWS",
            [
                IAM_ARN(
                    'root',
                    '',
                    self._config['parameters']['AccountNumber']
                )
            ]
        )

        action = Action(
            "s3",
            "*"
        )

        s3_arn1 = S3_ARN(
            resource = str(self._config['parameters']['UppercaseAwsEnvironmentPrefix'])+'-'+str(self._config['parameters']['UppercaseProjectName'])+'/*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        s3_arn2 = S3_ARN(
            resource = str(self._config['parameters']['UppercaseAwsEnvironmentPrefix'])+'-'+str(self._config['parameters']['UppercaseProjectName'])+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])

        )
        s3_arn3 = S3_ARN(
            resource = str(self._config['parameters']['UppercaseAwsEnvironmentPrefix'])+'-'+str(self._config['parameters']['LowercaseProjectName'])+'/*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])
        )
        s3_arn4 = S3_ARN(
            resource = str(self._config['parameters']['UppercaseAwsEnvironmentPrefix'])+'-'+str(self._config['parameters']['LowercaseProjectName'])+'*',
            account = str(self._config['parameters']['AccountNumber']),
            region = str(self._config['environment']['region'])

        )
        statement = Statement(
            Sid="S3Access",
            Effect=Allow,
            Action=[action],
            Resource=[s3_arn1,s3_arn2, s3_arn3, s3_arn4]
        )

        return statement


    def get_template(self):

        file_name = self.create_template()

        return file_name


