"""
The `~certbot_dns_route53.dns_route53` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Amazon Web Services Route 53 API.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Named Arguments
---------------

========================================  =====================================
``--dns-route53-credentials``             Load certbot style credentials from
                                          specified file. (Default: None)
``--dns-route53-awsprofile``              Specifies the AWS profile name to use.
                                          Used in combination with the standard
                                          AWS credential chain
                                          to select a specific block
                                          (e.g., [production]).
                                          (Default: default)
``--dns-route53-region``                  Overrides the default region behavior.
                                          If omitted, Boto3 will try to resolve
                                          by itself or via the
                                          CERTBOT_DNS_ROUTE53_REGION variable.
                                          Should be used if using Goverment
                                          cloud or other special environments 
                                          of AWS.
========================================  =====================================

Credentials
-----------
Use of this plugin requires a configuration file containing Amazon Web Services
API credentials for an account with the following permissions:

* ``route53:ListHostedZones``
* ``route53:GetChange``
* ``route53:ChangeResourceRecordSets``

These permissions can be captured in an AWS policy like the one below. Amazon
provides `information about managing access <https://docs.aws.amazon.com/Route53
/latest/DeveloperGuide/access-control-overview.html>`_ and `information about
the required permissions <https://docs.aws.amazon.com/Route53/latest
/DeveloperGuide/r53-api-permissions-ref.html>`_

.. code-block:: json
   :name: sample-aws-policy.json
   :caption: Example AWS policy file allowing only the creation of DNS-01 Challenge TXT Values

   {
       "Version": "2012-10-17",
       "Id": "certbot-dns-route53 sample policy",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "route53:ListHostedZones",
                   "route53:GetChange"
               ],
               "Resource": [
                   "*"
               ]
           },
           {
               "Effect": "Allow",
               "Action": [
                   "route53:ChangeResourceRecordSets"
               ],
               "Resource": [
                   "arn:aws:route53:::hostedzone/YOURHOSTEDZONEID"
               ],
               "Condition": {
                   "ForAllValues:StringLike": {
                       "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                           "_acme-challenge.*"
                       ]
                   },
                   "ForAllValues:StringEquals": {
                       "route53:ChangeResourceRecordSetsRecordTypes": [
                           "TXT"
                       ]
                   }
               }
           }
       ]
   }

The `access keys <https://docs.aws.amazon.com/general/latest/gr
/aws-sec-cred-types.html#access-keys-and-secret-access-keys>`_ for an account
with these permissions can be supplied either as

* a certbot style credentials ini file;

or

* An AWS shared credential files allowing you switch environments via parameters.
  AWS credential files are discussed in more detail in the Boto3 library's documentation about
  `configuring credentials <https://boto3.readthedocs.io/en/latest/guide/configuration.html#best-practices-for-configuring-credentials>`_. # pylint: disable=line-too-long

.. note::
   The Route53 DNS plugin is, given that Boto3 can handle the association, region agnostic.
   There are though several exceptions such as the AWS GovCloud which require
   (in all credential modalities) an explicit declaration of the region.

Hereby multiple options are implemented to provide the configuration:

Standard Configuration .ini File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Using the argument ``--dns-route53-credentials`` to provide a classical flat certbot
  configuration file.

Amazon Credential Files with Profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Using the argument ``--dns-route53-awscredentials`` to provide an AWS configuration file.
* Using the ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` environment
  variables.
* Using a credentials configuration file at the default location,
  ``~/.aws/credentials``. If you're running on sudo, the credentials
  will be picked up from the root home (/root/.aws/credentials).
* Using a credentials configuration file at a path supplied using the
  ``AWS_CONFIG_FILE`` environment variable.

.. code-block:: ini
   :name: config.ini
   :caption: Example of a standard certbot AWS credentials configuration file with regions:

   # Route53 API credentials used by Certbot
   aws_access_key_id=AKIAIOSFODNN7EXAMPLE
   aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   aws_region=us-east-1 # Optional

.. code-block:: ini
   :name: aws-shared-credentials.ini
   :caption: Example of a basic AWS credentials configuration file:

   [default]
   aws_access_key_id=AKIAIOSFODNN7EXAMPLE
   aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

.. code-block:: ini
   :name: ~/credentials or /root/credentials with multiple profiles
   :caption: Example of AWS credentials configuration file with multiple profiles:

   [Production]
   aws_access_key_id=AKIAIOSFODNN7EXAMPLE
   aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   [Staging]
   aws_access_key_id=AKIAIOSFODNN7EXAMPLE
   aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

**It is recommended to set ``--dns-route53-credentials``.** Otherwise Boto3 will
attempt to obtain credentials using files at ``$HOME`` or from
environment variables, which can differ at renewals. The following sources will
be tried (this is discussed in more detail in the Boto3 library's documentation
about `configuring credentials <https://boto3.readthedocs.io/en/latest
/guide/configuration.html#best-practices-for-configuring-credentials>`_):

* Using the ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` environment
  variables.
* Using a shared credentials file at the default location,
  ``~/.aws/credentials``.
* Using a shared credentials file at a path supplied using the
  ``AWS_SHARED_CREDENTIALS_FILE`` environment variable.
* Using a credentials configuration file at the default location,
  ``~/.aws/config``.
* Using a credentials configuration file at a path supplied using the
  ``AWS_CONFIG_FILE`` environment variable.

If none of the above methods are available and certbot is running in an EC2
instance which has an `IAM role attached <https://docs.aws.amazon.com/AWSEC2
/latest/UserGuide/iam-roles-for-amazon-ec2.html>`_, credentials for that role
will be used.

.. caution::
   You should protect these API credentials as you would a password. Users who
   can read this file can use these credentials to issue some types of API calls
   on your behalf, limited by the permissions assigned to the account. Users who
   can cause Certbot to run using these credentials can complete a ``dns-01``
   challenge to acquire new certificates or revoke existing certificates for
   domains these credentials are authorized to manage.


Examples
--------

Certbot Credential Files
~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   Certbot credential files do not support profiles. While certificates for multiple
   domains can be generated together, you should evaluate if multiple credential files
   are needed.

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com`` using a certbot
             credentials file

   certbot certonly \\
     --dns-route53 \\
     --dns-route53-credentials ~/.secrets/certbot/route53.ini \\
     -d example.com

AWS Credential Files
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com`` using AWS credential files
             credentials stored in ``~/.aws/credentials``

   certbot certonly \\
     --dns-route53 \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com`` AWS credential files stored in ``~/.aws/credentials``

   certbot certonly \\
     --dns-route53 \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com`` AWS credential files stored in ``~/.aws/credentials``
             using a specific profile

   AWS_PROFILE=route53-prod certbot certonly \\
     --dns-route53 \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com`` AWS credential files stored in specific locations
             on your system.

   AWS_SHARED_CREDENTIALS_FILE=/etc/certbot/aws/credentials \\
   certbot certonly \\
   --dns-route53 \\
   -d example.com
"""
