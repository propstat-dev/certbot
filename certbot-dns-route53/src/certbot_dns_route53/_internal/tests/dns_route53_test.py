"""Tests for certbot_dns_route53._internal.dns_route53.Authenticator"""

import sys
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
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        custom_creds = """[default]
dns_route53_profile=production
dns_route53_region=us-east-1

[production]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
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

    def test_credentials_file_no_section_header(self) -> None:
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        flat_creds = """aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
dns_route53_profile=production
dns_route53_region=us-east-1
this line has no equals sign and should just be skipped
"""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as credentials_file:
            credentials_file.write(flat_creds)
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

    def test_awscredentials_file_selects_profile_section(self) -> None:
        """--dns-route53-awscredentials must correctly distinguish between
        multiple, genuinely different credential sets in one file, selecting
        the section matching --dns-route53-profile."""
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

            with mock.patch(
                "certbot_dns_route53._internal.dns_route53.boto3.client"
            ) as mock_client:
                Authenticator(self.config, "route53")

                mock_client.assert_called_once_with(
                    "route53",
                    aws_access_key_id="AKIA_PRODUCTION_ACCOUNT_KEY",
                    aws_secret_access_key="production_account_secret",
                    aws_session_token=None,
                    region_name=None,
                )
        finally:
            os.unlink(credentials_file.name)

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
        should tolerate a read failure rather than crash -- SharedCredentialProvider
        still gets the chance to raise its own, clearer error afterward."""
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


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))
