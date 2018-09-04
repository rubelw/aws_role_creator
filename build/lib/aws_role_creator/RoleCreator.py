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

        if debug:
            self.debug = debug

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

        if 'template' in self._config['environment']:
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

    def get_template(self):

        context = self._config.get('meta-parameters', None)


        path = os.path.abspath(os.path.dirname(__file__))

        if self.template_type == 'project_role':
            print('is a project role')
            template_file = os.path.normpath(str(path)+'/canned_templates/projectrole.json.py')
        elif self.template_type == 'project_role_jump_account':
            template_file = os.path.normpath(str(path)+'/canned_templates/projectrole_jump_account.json.py')

        if self.debug:
            print('path: '+str(path))

        path, filename = os.path.split(template_file)

        if self.debug:
            print('path: '+str(path))
            print('filename: '+str(filename))

        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(path or './')
        )

        buf = env.get_template(filename).render(context)

        if self.debug:
            print('buf: '+str(buf))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.rdr', delete=False) as tmp:
            tmp.write(buf)
            logging.info('template rendered into {}'.format(tmp.name))

            self._config.pop('meta-parameters', None)

            return tmp.name

