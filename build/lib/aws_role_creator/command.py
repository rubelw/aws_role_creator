"""
The command line interface to cfn_nagger.

"""
from __future__ import absolute_import, division, print_function
import sys
import inspect
import logging
import os
import time
import traceback
from configparser import RawConfigParser
import boto3
import click
import aws_role_creator
from aws_role_creator import RoleCreator


def lineno():
    """Returns the current line number in our program."""
    return str(' - RoleCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


@click.group()
@click.version_option(version='0.0.10')
def cli():
    pass


@cli.command()
@click.option('--version', '-v', help='code version')
@click.option('--dryrun', '-d', help='dry run', is_flag=True)
@click.option('--no-poll', help='Start the stack work but do not poll', is_flag=True)
@click.option('--ini', '-i', help='INI file with needed information', required=False)
@click.option('--project-name', '-n', help='project name', required=False)
@click.option('--environment-abbreviation', '-e', help='environment abbreviation (i.e. dev, pd, sb,etc)', required=False)
@click.option('--aws-account-number', '-a', help='aws account number for role or account number for aws account role will jump to if project_role_jump_account', required=False)
@click.option('--bucket', '-b', help='bucket to upload cf template', required=False)
@click.option('--template-type', '-t', help='template type - whether a project_role or project_role_jump_account', required=False)
@click.option('--region', '-r', help='aws region', required=False)
@click.option('--aws-profile', '-p', help='aws profile', required=False)
@click.option('--aws-resources', '-w', help='comma delimited list of aws resources the role will have access to. Includes: ec2,cloudformation,s3,ecs,support,events,kms,waf,sns,states,iam,elasticloadbalancing,cloudwatch,cloudfront,elasticbeanstalk,ecr,autoscaling,dynamodb,sqs,acm,route53,codebuild,codepipeline,ssm,batch,apigateway,logs,elasticmapreduce', required=False)
@click.option('--template', '-m', help='cloudformation template path/name', required=False)
@click.option('--debug', help='Turn on debugging', required=False, is_flag=True)
def upsert(
        version,
        dryrun,
        no_poll,
        ini,
        project_name,
        environment_abbreviation,
        aws_account_number,
        bucket,
        template_type,
        region,
        aws_profile,
        aws_resources,
        template,
        debug
    ):
    '''
    Creates a new role
    '''

    # Must have ini data or project name, environment and aws account

    if not ini:
        if not project_name:
            print('Need project-name')
            sys.exit(1)
        if not environment_abbreviation:
            print('Need to have environment-abbreviation')
            sys.exit(1)
        if not aws_account_number:
            print('Need to have an aws-account-number')
            sys.exit(1)
        if not bucket:
            print('Need to specify a bucket')
            sys.exit(1)
        if not template_type:
            print('Need to specify a template type')
            sys.exit(1)
        if not region:
            print('Need to specify the AWS region')
            sys.exit(1)
        if not aws_profile:
            print('Need to specify the AWS profile')
            sys.exit(1)
        if not aws_resources and template_type != 'project_role_jump_account':
            print('Need to specify the AWS resources the role will have access to')
            sys.exit(1)

        if not template:

            if debug:
                print('there is not a template')

            template = None
        else:
            if debug:
                print('there is a template: '+str(template))

        ini_data = {}

        ini_data['environment']={}
        ini_data['environment']['bucket'] = bucket
        ini_data['environment']['template']=template
        ini_data['environment']['region']= region
        ini_data['environment']['stack_name'] = str(project_name)+'-role'
        ini_data['environment']['profile']=aws_profile

        ini_data['environment']['template_type'] = template_type

        ini_data['parameters']={}
        ini_data['parameters']['UppercaseAwsEnvironmentPrefix']= environment_abbreviation.upper()
        ini_data['parameters']['LowercaseAwsEnvironmentPrefix']= environment_abbreviation.lower()
        ini_data['parameters']['AccountNumber']= aws_account_number
        ini_data['parameters']['UppercaseProjectName']= project_name.upper()
        ini_data['parameters']['LowercaseProjectName']= project_name.lower()
        ini_data['parameters']['Resources']= aws_resources


        ini_data['meta-parameters']={}
        ini_data['meta-parameters']['RoleName'] = project_name.upper()

        ini_data['no_poll'] = bool(no_poll)
        ini_data['dryrun'] = bool(dryrun)

        ini_data['cwd'] = str(os.getcwd())

        if version:
            ini_data['codeVersion'] = version
        else:
            ini_data['codeVersion'] = str(int(time.time()))

        if version:
            myversion()
        else:
            start_create(
                ini_data,
                debug,
                project_name.upper()
            )

    else:
        ini_data = read_config_info(ini,debug)
        ini_data['cwd'] = str(os.getcwd())

        if 'environment' not in ini_data:
            print('[environment] section is required in the INI file')
            sys.exit(1)

        if 'template' in ini_data['environment']:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            ini_data['environment']['template']= str(dir_path)+'/'+str(ini_data['environment']['template'])
        else:
            ini_data['environment']['template']= None
        if 'region' not in ini_data['environment']:
            ini_data['environment']['region'] = find_myself()

        ini_data['no_poll'] = bool(no_poll)
        ini_data['dryrun'] = bool(dryrun)

        if 'template_type' not in ini_data['environment']:
            print('You need to specify template_type in environment section of ini file. It should be either \'project_role\' or \'project_role_jump_account\'.')
            sys.exit(1)
        elif ini_data['environment']['template_type'] not in ['project_role','project_role_jump_account']:
            print('template_type must be \'project_role\' or \'project_role_jump_account\'')
            sys.exit(1)

        if version:
            ini_data['codeVersion'] = version
        else:
            ini_data['codeVersion'] = str(int(time.time()))

        print(ini_data)

        if 'meta-parameters' in ini_data:
            if 'RoleName' in ini_data['meta-parameters']:
                role_name = ini_data['meta-parameters']['RoleName']
            else:
                print('Need to have RoleName in meta-parameters')
                sys.exit(1)

        else:
            print('Need to have meta-parameters in template to set the cloudformation template project name')
            sys.exit(1)

        if version:
            myversion()
        else:
            start_create(
                ini_data,
                debug,
                role_name
            )


@click.option('--version', '-v', help='Print version and exit', required=False, is_flag=True)
def version(version):
    """
    Get version
    """
    myversion()


def myversion():
    '''
    Gets the current version
    :return: current version
    '''
    print('Version: ' + str(aws_role_creator.__version__))

def start_create(
        ini,
        debug,
        role_name
    ):
    '''
    Starts the creation
    '''
    if debug:
        print('command - start_create'+lineno())
        print('ini data: '+str(ini)+lineno())



    creator = RoleCreator(ini, debug, role_name)
    if debug:
        print('print have RoleCreator')
    if creator.create():
        if debug:
            print('created')
    else:
        if debug:
            print('not created')

def find_myself():
    """
    Find myself
    Args:
        None
    Returns:
       An Amazon region
    """
    my_session = boto3.session.Session()
    return my_session.region_name

def read_config_info(ini_file,debug):
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
            the_stuff[str(section)] = {}
            for option in config.options(section):
                the_stuff[str(section)][str(option)] = str(config.get(section, option.replace('\n', '')))


        if debug:
            print('ini data: '+str(the_stuff))

        return the_stuff
    except Exception as wtf:
        logging.error('Exception caught in read_config_info(): {}'.format(wtf))
        traceback.print_exc(file=sys.stdout)
        return sys.exit(1)



