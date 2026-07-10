"""Tests for certbot_dns_route53._internal.dns_route53.Authenticator"""

import sys
import socket
import tempfile
import unittest
from typing import Any
from unittest import mock

from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
import josepy as jose
import pytest

from acme import challenges, messages
from certbot import achallenges
from certbot import errors
from certbot.compat import os
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import acme_util
from certbot.tests import util as test_util


CREDS_FILE = """[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

KEY = jose.jwk.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    # pylint: disable=protected-access

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01,
        identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=DOMAIN),
        account_key=KEY)

    def setUp(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        super().setUp()

        self.config = mock.MagicMock(
            route53_credentials=None,
            route53_awscredentials=None,
            route53_profile=None,
            route53_region=None,
        )

        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        self.auth = Authenticator(self.config, "route53")

    def tearDown(self) -> None:
        if "AWS_ACCESS_KEY_ID" in os.environ:
            del os.environ["AWS_ACCESS_KEY_ID"]
        if "AWS_SECRET_ACCESS_KEY" in os.environ:
            del os.environ["AWS_SECRET_ACCESS_KEY"]
        if "CERTBOT_DNS_ROUTE53_PROFILE" in os.environ:
            del os.environ["CERTBOT_DNS_ROUTE53_PROFILE"]
        if "CERTBOT_DNS_ROUTE53_REGION" in os.environ:
            del os.environ["CERTBOT_DNS_ROUTE53_REGION"]

    def test_more_info(self) -> None:
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self) -> None:
        self.assertEqual(self.auth.get_chall_pref("example.org"), [challenges.DNS01])

    def test_credentials_file(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(CREDS_FILE)
            credentials_file.close()

        try:
            self.config.route53_credentials = credentials_file.name

            with mock.patch(
                "certbot_dns_route53._internal.dns_route53.boto3.client"
            ) as mock_client:
                Authenticator(self.config, "route53")

                mock_client.assert_called_once_with(
                    "route53",
                    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    aws_session_token=None,
                    region_name=None,
                )
        finally:
            os.unlink(credentials_file.name)

    def test_credentials_file_with_inline_configs(self) -> None:
        """No [section] header required, an inline dns_route53_region
        override flows through to region_name, and a stray line with no
        '=' is tolerated rather than breaking parsing."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        custom_creds = """aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
dns_route53_profile=production
dns_route53_region=us-east-1
this line has no equals sign and should just be skipped
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(custom_creds)
            credentials_file.close()

        try:
            self.config.route53_credentials = credentials_file.name

            with mock.patch(
                "certbot_dns_route53._internal.dns_route53.boto3.client"
            ) as mock_client:
                Authenticator(self.config, "route53")

                mock_client.assert_called_once_with(
                    "route53",
                    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    aws_session_token=None,
                    region_name="us-east-1",
                )
        finally:
            os.unlink(credentials_file.name)

    def test_credentials_file_not_found(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config.route53_credentials = "/missing/file.ini"

        with mock.patch("certbot_dns_route53._internal.dns_route53.os.path.exists", return_value=False):
            with self.assertRaises(errors.PluginError):
                Authenticator(self.config, "route53")

    def test_awscredentials_file_inline_profile_pointer(self) -> None:
        """--dns-route53-awscredentials with the profile/region specified
        inline (in [default]) rather than via a CLI flag."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        custom_creds = """[default]
dns_route53_profile = production
dns_route53_region = us-east-1

[production]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(custom_creds)
            credentials_file.close()

        try:
            self.config.route53_awscredentials = credentials_file.name

            with mock.patch(
                "certbot_dns_route53._internal.dns_route53.boto3.Session"
            ) as mock_session:
                Authenticator(self.config, "route53")

                mock_session.assert_called_once_with(
                    profile_name="production", region_name="us-east-1",
                )
                mock_session.return_value.client.assert_called_once_with("route53")
        finally:
            os.unlink(credentials_file.name)

    def test_awscredentials_file_not_found(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config.route53_awscredentials = "/missing/file.ini"

        with mock.patch("certbot_dns_route53._internal.dns_route53.os.path.exists", return_value=False):
            with self.assertRaises(errors.PluginError):
                Authenticator(self.config, "route53")

    def test_credentials_and_awscredentials_are_mutually_exclusive(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config.route53_credentials = "/a.ini"
        self.config.route53_awscredentials = "/b.ini"

        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")

    def test_no_credentials_file_uses_profile_region_session(self) -> None:
        """Legacy path: no credentials file at all, but --dns-route53-profile
        and/or --dns-route53-region given -- should build a boto3.Session
        against the standard AWS credential chain."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config.route53_profile = "myprofile"
        self.config.route53_region = "eu-west-1"

        with mock.patch(
            "certbot_dns_route53._internal.dns_route53.boto3.Session"
        ) as mock_session:
            Authenticator(self.config, "route53")

            mock_session.assert_called_once_with(
                profile_name="myprofile", region_name="eu-west-1",
            )
            mock_session.return_value.client.assert_called_once_with("route53")

    def test_credentials_file_session_token(self) -> None:
        """A flat credentials file may also carry a temporary
        aws_session_token, which should be passed through."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        creds_with_token = """aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token=FQoGZXIvYXdzEXAMPLETOKEN
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(creds_with_token)
            credentials_file.close()

        try:
            self.config.route53_credentials = credentials_file.name

            with mock.patch(
                "certbot_dns_route53._internal.dns_route53.boto3.client"
            ) as mock_client:
                Authenticator(self.config, "route53")

                mock_client.assert_called_once_with(
                    "route53",
                    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    aws_session_token="FQoGZXIvYXdzEXAMPLETOKEN",
                    region_name=None,
                )
        finally:
            os.unlink(credentials_file.name)

    def test_credentials_file_profile_only_falls_back_to_session(self) -> None:
        """A flat credentials file with no literal keys, only a profile
        pointer, should fall back to the standard AWS profile chain."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        profile_only = "dns_route53_profile=myprofile\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(profile_only)
            credentials_file.close()

        try:
            self.config.route53_credentials = credentials_file.name

            with mock.patch(
                "certbot_dns_route53._internal.dns_route53.boto3.Session"
            ) as mock_session:
                Authenticator(self.config, "route53")

                mock_session.assert_called_once_with(
                    profile_name="myprofile", region_name=None,
                )
                mock_session.return_value.client.assert_called_once_with("route53")
        finally:
            os.unlink(credentials_file.name)

    def test_credentials_file_no_keys_no_profile_raises(self) -> None:
        """A flat credentials file with neither literal keys nor a profile
        pointer gives the plugin nothing to work with."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        empty_of_useful_content = "dns_route53_region=us-east-1\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(empty_of_useful_content)
            credentials_file.close()

        try:
            self.config.route53_credentials = credentials_file.name
            with self.assertRaises(errors.PluginError):
                Authenticator(self.config, "route53")
        finally:
            os.unlink(credentials_file.name)

    def test_awscredentials_file_profile_not_found_raises(self) -> None:
        """--dns-route53-awscredentials where --dns-route53-profile points
        at a section that doesn't exist in the file."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(CREDS_FILE)  # only has [default]
            credentials_file.close()

        try:
            self.config.route53_awscredentials = credentials_file.name
            self.config.route53_profile = "does-not-exist"

            with self.assertRaises(errors.PluginError):
                Authenticator(self.config, "route53")
        finally:
            os.unlink(credentials_file.name)

    def test_add_parser_arguments(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        added = []

        def fake_add(name: str, **kwargs: Any) -> None:
            added.append(name)

        Authenticator.add_parser_arguments(fake_add)
        self.assertEqual(
            set(added), {"credentials", "awscredentials", "profile", "region"}
        )

    def test_auth_hint(self) -> None:
        hint = self.auth.auth_hint([])
        self.assertIn("dns-route53", hint)

    def test_prepare(self) -> None:
        self.auth.prepare()  # should not raise

    def test_credentials_file_unreadable_raises_plugin_error(self) -> None:
        """If the file exists but can't actually be opened (e.g. permission
        denied), that should surface as a PluginError, not a raw OSError."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config.route53_credentials = "/some/existing/path.ini"

        with mock.patch("certbot_dns_route53._internal.dns_route53.os.path.exists", return_value=True), \
             mock.patch("builtins.open", side_effect=PermissionError("denied")):
            with self.assertRaises(errors.PluginError):
                Authenticator(self.config, "route53")

    def test_awscredentials_file_unreadable_inline_scan_is_tolerant(self) -> None:
        """The inline profile/region scan for --dns-route53-awscredentials
        should tolerate a read failure rather than crash -- boto3's own
        credential resolution still gets the chance to raise its own,
        clearer error afterward."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(CREDS_FILE)
            credentials_file.close()

        try:
            self.config.route53_awscredentials = credentials_file.name

            # os.path.exists sees the real file (so we get past the initial
            # check), but the inline-override scan's own open() call fails.
            real_open = open

            def flaky_open(path: str, *args: Any, **kwargs: Any) -> Any:
                if path == credentials_file.name:
                    raise OSError("simulated transient read failure")
                return real_open(path, *args, **kwargs)

            with mock.patch("builtins.open", side_effect=flaky_open):
                with self.assertRaises(errors.PluginError):
                    Authenticator(self.config, "route53")
        finally:
            os.unlink(credentials_file.name)

    def test_awscredentials_file_real_resolution_selects_correct_profile(self) -> None:
        """End-to-end, with no boto3 mocking: a real multi-section
        AWS-style file resolves the actual keys for the requested profile,
        not just the right constructor arguments. setUp() already leaves
        AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY set to dummy values in the
        environment for every test in this class, so this also doubles as
        an end-to-end check that those ambient values don't leak into the
        resolved client instead of the file's real keys."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        multi_profile_creds = """[default]
aws_access_key_id = AKIA_DEFAULT_ACCOUNT_KEY
aws_secret_access_key = default_account_secret

[production]
aws_access_key_id = AKIA_PRODUCTION_ACCOUNT_KEY
aws_secret_access_key = production_account_secret
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(multi_profile_creds)
            credentials_file.close()

        try:
            self.config.route53_awscredentials = credentials_file.name
            self.config.route53_profile = "production"

            auth = Authenticator(self.config, "route53")
            creds = auth.r53._request_signer._credentials
            self.assertEqual(creds.access_key, "AKIA_PRODUCTION_ACCOUNT_KEY")
            self.assertEqual(creds.secret_key, "production_account_secret")
        finally:
            os.unlink(credentials_file.name)

    def test_ec2_instance_role_path_unaffected_by_awscredentials_isolation(self) -> None:
        """The IMDS/container-credential isolation added to
        --dns-route53-awscredentials must not leak into the separate,
        untouched legacy path (no credentials file at all) that real
        EC2-instance-role deployments rely on -- the most common way to
        run this plugin on EC2. Confirms, with a mocked IMDS response
        standing in for an attached instance role:
          1. the legacy no-file path resolves via the instance role,
          2. --dns-route53-awscredentials with a *valid* file resolves
             from the file without ever touching the (mocked) IMDS
             endpoint at all,
          3. a legacy-path Authenticator constructed *after* that -- as
             certbot renew would for a second lineage -- still resolves
             via the instance role, proving nothing leaked."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        # setUp() leaves ambient dummy AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
        # set for the other tests in this class; remove them here so the
        # legacy path actually has to fall through to the (mocked) instance
        # role rather than resolving from those first.
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

        # boto3.client(...) (the legacy path's implementation) reuses a
        # process-global default session that caches its first resolved
        # credentials -- unrelated to anything in this PR, but setUp()
        # already triggered one resolution using the dummy env vars above,
        # so reset it here to get a genuinely fresh resolution.
        import boto3
        boto3.DEFAULT_SESSION = None

        fake_role_creds = {
            "access_key": "AKIAEC2ROLEEXAMPLE",
            "secret_key": "ec2rolesecret",
            "token": "ec2roletoken",
            "expiry_time": "2099-01-01T00:00:00Z",
            "role_name": "fake-ec2-instance-role",
        }

        with mock.patch(
            "botocore.utils.InstanceMetadataFetcher.retrieve_iam_role_credentials",
            return_value=fake_role_creds,
        ) as mock_imds:
            # (1) legacy path -- no credentials file at all
            legacy_config = mock.MagicMock(
                route53_credentials=None, route53_awscredentials=None,
                route53_profile=None, route53_region=None,
            )
            legacy_auth = Authenticator(legacy_config, "route53")
            self.assertEqual(
                legacy_auth.r53._request_signer._credentials.access_key,
                "AKIAEC2ROLEEXAMPLE",
            )
            self.assertTrue(mock_imds.called)
            mock_imds.reset_mock()

            # (2) --dns-route53-awscredentials with a *valid* file resolves
            # from the file and never even calls the mocked IMDS provider
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
                credentials_file.write(
                    "[default]\naws_access_key_id = AKIAFROMFILE\n"
                    "aws_secret_access_key = filesecret\n"
                )
                credentials_file.close()

            try:
                aws_config = mock.MagicMock(
                    route53_credentials=None,
                    route53_awscredentials=credentials_file.name,
                    route53_profile=None, route53_region=None,
                )
                aws_auth = Authenticator(aws_config, "route53")
                self.assertEqual(
                    aws_auth.r53._request_signer._credentials.access_key,
                    "AKIAFROMFILE",
                )
                self.assertFalse(mock_imds.called)
            finally:
                os.unlink(credentials_file.name)

            # (3) a subsequent legacy-path lineage still resolves via the
            # instance role -- the isolation from (2) didn't leak into it
            boto3.DEFAULT_SESSION = None
            legacy_auth_2 = Authenticator(legacy_config, "route53")
            self.assertEqual(
                legacy_auth_2.r53._request_signer._credentials.access_key,
                "AKIAEC2ROLEEXAMPLE",
            )
            self.assertTrue(mock_imds.called)

    def test_awscredentials_file_ambient_aws_profile_does_not_override(self) -> None:
        """An ambient AWS_PROFILE env var must not silently substitute for
        --dns-route53-profile / the file's own [default] section."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        multi_profile_creds = """[default]
aws_access_key_id = AKIA_DEFAULT_ACCOUNT_KEY
aws_secret_access_key = default_account_secret

[other]
aws_access_key_id = AKIA_OTHER_ACCOUNT_KEY
aws_secret_access_key = other_account_secret
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(multi_profile_creds)
            credentials_file.close()

        os.environ["AWS_PROFILE"] = "other"
        try:
            self.config.route53_awscredentials = credentials_file.name
            # route53_profile stays None -- must resolve the file's own
            # [default] section, not whatever AWS_PROFILE points at.

            auth = Authenticator(self.config, "route53")
            creds = auth.r53._request_signer._credentials
            self.assertEqual(creds.access_key, "AKIA_DEFAULT_ACCOUNT_KEY")
        finally:
            os.unlink(credentials_file.name)
            del os.environ["AWS_PROFILE"]

    def test_awscredentials_file_role_arn_in_aws_config_not_consulted(self) -> None:
        """A role_arn under a same-named profile in the system's real
        ~/.aws/config must never be consulted -- otherwise boto3 would try
        an STS AssumeRole call instead of using the static keys in the
        file the user explicitly pointed us at."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        from certbot.compat import filesystem

        with tempfile.TemporaryDirectory() as fake_home:
            aws_dir = os.path.join(fake_home, ".aws")
            filesystem.makedirs(aws_dir)

            # certbot forbids the builtin open()/os.makedirs() for writing
            # files directly; filesystem.open() (paired with os.fdopen(),
            # matching certbot's own internal usage pattern) is the
            # sanctioned low-level equivalent.
            config_path = os.path.join(aws_dir, "config")
            fd = filesystem.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(
                    "[profile shared]\n"
                    "role_arn = arn:aws:iam::123456789012:role/example\n"
                    "source_profile = shared\n"
                )

            with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
                credentials_file.write(
                    "[shared]\n"
                    "aws_access_key_id = AKIASHAREDSTATIC\n"
                    "aws_secret_access_key = sharedstaticsecret\n"
                )
                credentials_file.close()

            try:
                self.config.route53_awscredentials = credentials_file.name
                self.config.route53_profile = "shared"

                old_home = os.environ.get("HOME")
                os.environ["HOME"] = fake_home
                try:
                    auth = Authenticator(self.config, "route53")
                    creds = auth.r53._request_signer._credentials
                    self.assertEqual(creds.access_key, "AKIASHAREDSTATIC")
                finally:
                    if old_home is None:
                        del os.environ["HOME"]
                    else:
                        os.environ["HOME"] = old_home
            finally:
                os.unlink(credentials_file.name)

    def test_renew_sequential_authenticators_do_not_leak_credentials(self) -> None:
        """certbot renew constructs a fresh Authenticator per lineage,
        sequentially, in one process. Two lineages using
        --dns-route53-awscredentials with the SAME profile name but
        DIFFERENT files must each resolve their own file's keys, with no
        leakage between them."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as file_a:
            file_a.write("[prod]\naws_access_key_id = AKIALINEAGEA\n"
                          "aws_secret_access_key = lineageasecret\n")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as file_b:
            file_b.write("[prod]\naws_access_key_id = AKIALINEAGEB\n"
                          "aws_secret_access_key = lineagebsecret\n")

        try:
            config_a = mock.MagicMock(
                route53_credentials=None, route53_awscredentials=file_a.name,
                route53_profile="prod", route53_region=None,
            )
            config_b = mock.MagicMock(
                route53_credentials=None, route53_awscredentials=file_b.name,
                route53_profile="prod", route53_region=None,
            )

            auth_a = Authenticator(config_a, "route53")
            self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", os.environ)

            auth_b = Authenticator(config_b, "route53")
            self.assertNotIn("AWS_SHARED_CREDENTIALS_FILE", os.environ)

            self.assertEqual(
                auth_a.r53._request_signer._credentials.access_key, "AKIALINEAGEA")
            self.assertEqual(
                auth_b.r53._request_signer._credentials.access_key, "AKIALINEAGEB")
        finally:
            os.unlink(file_a.name)
            os.unlink(file_b.name)

    def test_renew_sequential_mixed_awscredentials_then_flat_credentials(self) -> None:
        """One lineage using --dns-route53-awscredentials followed by
        another using --dns-route53-credentials, back to back in the same
        process -- the second must resolve correctly with nothing left
        over from the first."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as file_a:
            file_a.write("[prod]\naws_access_key_id = AKIAAWSSTYLE\n"
                          "aws_secret_access_key = awsstylesecret\n")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as file_b:
            file_b.write("aws_access_key_id=AKIAFLATSTYLE\n"
                          "aws_secret_access_key=flatstylesecret\n")

        try:
            config_a = mock.MagicMock(
                route53_credentials=None, route53_awscredentials=file_a.name,
                route53_profile="prod", route53_region=None,
            )
            config_b = mock.MagicMock(
                route53_credentials=file_b.name, route53_awscredentials=None,
                route53_profile=None, route53_region=None,
            )

            auth_a = Authenticator(config_a, "route53")
            auth_b = Authenticator(config_b, "route53")

            self.assertEqual(
                auth_a.r53._request_signer._credentials.access_key, "AKIAAWSSTYLE")
            self.assertEqual(
                auth_b.r53._request_signer._credentials.access_key, "AKIAFLATSTYLE")
        finally:
            os.unlink(file_a.name)
            os.unlink(file_b.name)

    def test_awscredentials_file_no_valid_keys_never_hits_network(self) -> None:
        """When the requested profile section exists but has no usable
        keys, get_credentials() exhausts the whole resolver chain, which
        (verified empirically via CI: an unclosed-socket warning to
        169.254.169.254 surfaced on an unrelated test) falls through to
        the EC2 instance-metadata-service provider and makes a real
        network connection. On real EC2/ECS/EKS infrastructure -- exactly
        where this plugin commonly runs -- that could silently authenticate
        as the instance's own IAM identity instead of raising a clear
        error about the file. This must never touch the network at all."""
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        # [default] section exists (so boto3.Session doesn't raise
        # ProfileNotFound), but has no actual keys -- forces get_credentials()
        # to exhaust every provider in the chain before giving up.
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write("[default]\n")
            credentials_file.close()

        def spy_connect(self: Any, address: Any, *a: Any, **kw: Any) -> Any:
            raise AssertionError(
                f"credential resolution made a real network connection to {address} "
                "-- AWS_EC2_METADATA_DISABLED/container-credential isolation regressed"
            )

        try:
            self.config.route53_awscredentials = credentials_file.name

            with mock.patch.object(socket.socket, "connect", spy_connect):
                with self.assertRaises(errors.PluginError):
                    Authenticator(self.config, "route53")
        finally:
            os.unlink(credentials_file.name)

    def test_perform(self) -> None:
        with mock.patch.object(self.auth, "_change_txt_record") as mock_change, \
             mock.patch.object(self.auth, "_wait_for_change") as mock_wait:

            self.auth.perform([self.achall])

            mock_change.assert_called_once_with(
                "UPSERT",
                "_acme-challenge." + DOMAIN,
                mock.ANY,
            )
            self.assertEqual(mock_wait.call_count, 1)

    def test_perform_no_credentials_error(self) -> None:
        with mock.patch.object(self.auth, "_change_txt_record", side_effect=NoCredentialsError):
            with pytest.raises(errors.PluginError):
                self.auth.perform([self.achall])

    def test_perform_client_error(self) -> None:
        err = ClientError({"Error": {"Code": "foo"}}, "bar")
        with mock.patch.object(self.auth, "_change_txt_record", side_effect=err):
            with pytest.raises(errors.PluginError):
                self.auth.perform([self.achall])

    def test_cleanup(self) -> None:
        self.auth._attempt_cleanup = True
        with mock.patch.object(self.auth, "_change_txt_record") as mock_change:
            self.auth.cleanup([self.achall])

            mock_change.assert_called_once_with(
                "DELETE",
                "_acme-challenge." + DOMAIN,
                mock.ANY,
            )

    def test_cleanup_no_credentials_error(self) -> None:
        self.auth._attempt_cleanup = True
        with mock.patch.object(self.auth, "_change_txt_record", side_effect=NoCredentialsError):
            self.auth.cleanup([self.achall])

    def test_cleanup_client_error(self) -> None:
        self.auth._attempt_cleanup = True
        err = ClientError({"Error": {"Code": "foo"}}, "bar")
        with mock.patch.object(self.auth, "_change_txt_record", side_effect=err):
            self.auth.cleanup([self.achall])


class ClientTest(unittest.TestCase):
    # pylint: disable=protected-access

    PRIVATE_ZONE = {"Id": "BAD-PRIVATE", "Name": "example.com", "Config": {"PrivateZone": True}}
    EXAMPLE_NET_ZONE = {"Id": "BAD-WRONG-TLD", "Name": "example.net", "Config": {"PrivateZone": False}}
    EXAMPLE_COM_ZONE = {"Id": "EXAMPLE", "Name": "example.com", "Config": {"PrivateZone": False}}
    FOO_EXAMPLE_COM_ZONE = {"Id": "FOO", "Name": "foo.example.com", "Config": {"PrivateZone": False}}

    def setUp(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config = mock.MagicMock()
        self.config.conf.return_value = None

        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        self.client = Authenticator(self.config, "route53")

    def tearDown(self) -> None:
        if "AWS_ACCESS_KEY_ID" in os.environ:
            del os.environ["AWS_ACCESS_KEY_ID"]
        if "AWS_SECRET_ACCESS_KEY" in os.environ:
            del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_find_zone_id_for_domain(self) -> None:
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {"HostedZones": [self.EXAMPLE_NET_ZONE, self.EXAMPLE_COM_ZONE]}
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        self.assertEqual(result, "EXAMPLE")

    def test_find_zone_id_for_domain_pagination(self) -> None:
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {"HostedZones": [self.PRIVATE_ZONE, self.EXAMPLE_COM_ZONE]},
            {"HostedZones": [self.PRIVATE_ZONE, self.FOO_EXAMPLE_COM_ZONE]}
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        self.assertEqual(result, "FOO")

    def test_find_zone_id_for_domain_no_results(self) -> None:
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = []

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_change_txt_record(self) -> None:
        with mock.patch.object(self.client, "_find_zone_id_for_domain"):
            self.client.r53.change_resource_record_sets = mock.MagicMock(
                return_value={"ChangeInfo": {"Id": 1}},
            )

            self.client._change_txt_record("FOO", DOMAIN, "foo")
            self.assertEqual(self.client.r53.change_resource_record_sets.call_count, 1)

    def test_change_txt_record_duplicate(self) -> None:
        """Some ACME CAs return identical DNS-01 challenge values for the
        apex and wildcard of the same domain. Route53 rejects a
        ResourceRecordSet containing duplicate values, so the second UPSERT
        for the same (domain, value) pair must be a no-op that reuses the
        first change_id rather than re-submitting."""
        with mock.patch.object(self.client, "_find_zone_id_for_domain"):
            self.client.r53.change_resource_record_sets = mock.MagicMock(
                return_value={"ChangeInfo": {"Id": "first-change-id"}})

            # First call should go through
            change_id = self.client._change_txt_record("UPSERT", DOMAIN, "same-value")
            self.assertEqual(change_id, "first-change-id")
            self.assertEqual(self.client.r53.change_resource_record_sets.call_count, 1)

            # Second call with same domain and value should return previous change ID
            change_id = self.client._change_txt_record("UPSERT", DOMAIN, "same-value")
            self.assertEqual(change_id, "first-change-id")
            self.assertEqual(self.client.r53.change_resource_record_sets.call_count, 1)

    def test_change_txt_record_delete(self) -> None:
        with mock.patch.object(self.client, "_find_zone_id_for_domain"):
            self.client.r53.change_resource_record_sets = mock.MagicMock(
                return_value={"ChangeInfo": {"Id": 1}},
            )

            validation = "some-value"
            validation_record = {"Value": '"{0}"'.format(validation)}
            self.client._resource_records[DOMAIN] = [validation_record]

            self.client._change_txt_record("DELETE", DOMAIN, validation)
            self.assertEqual(self.client.r53.change_resource_record_sets.call_count, 1)

    def test_change_txt_record_delete_with_remaining_records(self) -> None:
        """Deleting one TXT value while others remain for the same domain
        should UPSERT the rrset rather than delete it outright."""
        with mock.patch.object(self.client, "_find_zone_id_for_domain"):
            self.client.r53.change_resource_record_sets = mock.MagicMock(
                return_value={"ChangeInfo": {"Id": 1}},
            )

            validation = "some-value"
            other_validation_record = {"Value": '"other-value"'}
            validation_record = {"Value": '"{0}"'.format(validation)}
            self.client._resource_records[DOMAIN] = [other_validation_record, validation_record]

            self.client._change_txt_record("DELETE", DOMAIN, validation)

            call_kwargs = self.client.r53.change_resource_record_sets.call_args.kwargs
            action_used = call_kwargs["ChangeBatch"]["Changes"][0]["Action"]
            self.assertEqual(action_used, "UPSERT")

    def test_wait_for_change(self) -> None:
        self.client.r53.get_change = mock.MagicMock(
            side_effect=[
                {"ChangeInfo": {"Status": "PENDING"}},
                {"ChangeInfo": {"Status": "INSYNC"}},
            ],
        )

        self.client._wait_for_change("1")
        self.assertTrue(self.client.r53.get_change.called)

    def test_wait_for_change_times_out(self) -> None:
        self.client.r53.get_change = mock.MagicMock(
            return_value={"ChangeInfo": {"Status": "PENDING"}},
        )

        with mock.patch("certbot_dns_route53._internal.dns_route53.time.sleep"):
            with self.assertRaises(errors.PluginError):
                self.client._wait_for_change("1")


class ParseFlatKeyValueFileTest(unittest.TestCase):
    """Direct coverage for the shared line-parser both
    _scan_inline_overrides and _client_from_flat_credentials_file now
    delegate to, instead of each duplicating their own line-by-line scan."""
    # pylint: disable=protected-access

    def test_parses_all_recognized_fields(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import _parse_flat_key_value_file

        content = """aws_access_key_id=AKIAEXAMPLE
aws_secret_access_key=secretexample
aws_session_token=tokenexample
dns_route53_profile=myprofile
dns_route53_region=us-east-1
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            f.close()
        try:
            fields = _parse_flat_key_value_file(f.name)
            self.assertEqual(fields.access_key, "AKIAEXAMPLE")
            self.assertEqual(fields.secret_key, "secretexample")
            self.assertEqual(fields.session_token, "tokenexample")
            self.assertEqual(fields.profile, "myprofile")
            self.assertEqual(fields.region, "us-east-1")
        finally:
            os.unlink(f.name)

    def test_skips_comments_blank_lines_and_section_headers(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import _parse_flat_key_value_file

        content = """# a comment
; another comment style

[default]
aws_access_key_id=AKIAEXAMPLE
aws_secret_access_key=secretexample
this line has no equals sign and should just be skipped
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            f.close()
        try:
            fields = _parse_flat_key_value_file(f.name)
            self.assertEqual(fields.access_key, "AKIAEXAMPLE")
            self.assertEqual(fields.secret_key, "secretexample")
            self.assertIsNone(fields.profile)
            self.assertIsNone(fields.region)
        finally:
            os.unlink(f.name)

    def test_first_occurrence_wins_across_key_aliases(self) -> None:
        """dns_route53_profile and certbot_dns_route53_profile are aliases
        for the same field -- whichever appears first in the file wins,
        regardless of which alias it is."""
        from certbot_dns_route53._internal.dns_route53 import _parse_flat_key_value_file

        content = """dns_route53_profile=first-alias-wins
certbot_dns_route53_profile=second-alias-loses
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            f.close()
        try:
            fields = _parse_flat_key_value_file(f.name)
            self.assertEqual(fields.profile, "first-alias-wins")
        finally:
            os.unlink(f.name)

    def test_reversed_alias_order_still_honors_file_order(self) -> None:
        """Same as above but with the aliases appearing in the opposite
        order, to confirm it's file line order that decides -- not the
        order aliases happen to be listed in code."""
        from certbot_dns_route53._internal.dns_route53 import _parse_flat_key_value_file

        content = """certbot_dns_route53_profile=first-alias-wins
dns_route53_profile=second-alias-loses
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            f.close()
        try:
            fields = _parse_flat_key_value_file(f.name)
            self.assertEqual(fields.profile, "first-alias-wins")
        finally:
            os.unlink(f.name)

    def test_values_are_stripped_of_surrounding_quotes(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import _parse_flat_key_value_file

        content = """aws_access_key_id="AKIAEXAMPLE"
aws_secret_access_key='secretexample'
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            f.close()
        try:
            fields = _parse_flat_key_value_file(f.name)
            self.assertEqual(fields.access_key, "AKIAEXAMPLE")
            self.assertEqual(fields.secret_key, "secretexample")
        finally:
            os.unlink(f.name)

    def test_missing_file_raises_oserror(self) -> None:
        """Raises rather than swallowing the error -- each caller decides
        for itself how strictly to treat a read failure."""
        from certbot_dns_route53._internal.dns_route53 import _parse_flat_key_value_file

        with self.assertRaises(OSError):
            _parse_flat_key_value_file("/nonexistent/path/to/creds.ini")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))
