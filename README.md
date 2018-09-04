AWS Role Creator
========================

Features
========

aws-role-creator creates an aws role.

There are two types of roles it creates.  It creates a role in the AWS Jump Account which allows you to
assume a role in another account, or it create a standard role.

Installation
============

aws-role-creator is on PyPI so all you need is:

    $ pip install aws-role-creator

Example
=======

Getting help

    $ role-creator upsert --help
    Usage: role-creator upsert [OPTIONS]

       primary function for creating a bucket :return:

     Options:
       -v, --version TEXT  code version
       -d, --dryrun        dry run
       --no-poll           Start the stack work but do not poll
       -i, --ini TEXT      INI file with needed information  [required]
       --debug             Turn on debugging
       --help              Show this message and exit.

    role-creator upsert -i config/my.ini

Example Ini file

    [environment]
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

    [meta-parameters]
    RoleName = my-role


