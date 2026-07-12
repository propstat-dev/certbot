"""Tests for certbot_dns_route53._internal.dns_route53.Authenticator"""

import gc
import sys
import tempfile
import unittest
import warnings
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

KEY = jose.jwk.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    # pylint: disable=protected-access

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01,
        identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=DOMAIN),
        account_key=KEY)

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        super().setUp()

        self.config = mock.MagicMock()

        # Set up dummy credentials for testing
        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        # _log_resolved_credentials makes a real sts:GetCallerIdentity call to
        # verify+log the resolved identity whenever credentials resolve
        # successfully. With these dummy-but-resolvable env credentials,
        # constructing an Authenticator would otherwise open a real
        # connection to AWS on every single test -- slow/flaky, and on old
        # botocore (no working client.close()) it leaks an unclosed SSL
        # socket that surfaces as a ResourceWarning failure in some unrelated
        # test once pytest's unraisable-exception hook catches up with it.
        # This is covered in isolation by ResolvedCredentialsLoggingTest, so
        # it doesn't need to run for real here.
        patcher = mock.patch(
            "certbot_dns_route53._internal.dns_route53._log_resolved_credentials")
        self.addCleanup(patcher.stop)
        patcher.start()

        self.auth = Authenticator(self.config, "route53")

    def tearDown(self):
        # Remove the dummy credentials from env vars
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_more_info(self) -> None:
        self.assertTrue(isinstance(self.auth.more_info(), str))

    def test_get_chall_pref(self) -> None:
        self.assertEqual(self.auth.get_chall_pref("example.org"), [challenges.DNS01])

    def test_perform(self):
        self.auth._change_txt_record = mock.MagicMock() # type: ignore[method-assign, unused-ignore]
        self.auth._wait_for_change = mock.MagicMock() # type: ignore [method-assign, unused-ignore]

        self.auth.perform([self.achall])

        self.auth._change_txt_record.assert_called_once_with("UPSERT",
                                                             '_acme-challenge.' + DOMAIN,
                                                             mock.ANY)
        assert self.auth._wait_for_change.call_count == 1

    def test_perform_no_credentials_error(self):
        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
            side_effect=NoCredentialsError)

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_perform_client_error(self):
        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
            side_effect=ClientError({"Error": {"Code": "foo"}}, "bar"))

        with pytest.raises(errors.PluginError):
            self.auth.perform([self.achall])

    def test_cleanup(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock() # type: ignore[method-assign, unused-ignore]

        self.auth.cleanup([self.achall])

        self.auth._change_txt_record.assert_called_once_with("DELETE",
                                                             '_acme-challenge.'+DOMAIN,
                                                             mock.ANY)

    def test_cleanup_no_credentials_error(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
        side_effect=NoCredentialsError)

        self.auth.cleanup([self.achall])

    def test_cleanup_client_error(self):
        self.auth._attempt_cleanup = True

        self.auth._change_txt_record = mock.MagicMock( # type: ignore [method-assign, unused-ignore]
            side_effect=ClientError({"Error": {"Code": "foo"}}, "bar"))

        self.auth.cleanup([self.achall])


class ClientTest(unittest.TestCase):
    # pylint: disable=protected-access

    PRIVATE_ZONE = {
                        "Id": "BAD-PRIVATE",
                        "Name": "example.com",
                        "Config": {
                            "PrivateZone": True
                        }
                    }

    EXAMPLE_NET_ZONE = {
                            "Id": "BAD-WRONG-TLD",
                            "Name": "example.net",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    EXAMPLE_COM_ZONE = {
                            "Id": "EXAMPLE",
                            "Name": "example.com",
                            "Config": {
                                "PrivateZone": False
                            }
                        }

    FOO_EXAMPLE_COM_ZONE = {
                                "Id": "FOO",
                                "Name": "foo.example.com",
                                "Config": {
                                    "PrivateZone": False
                                }
                            }

    def setUp(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator

        self.config = mock.MagicMock()

        # Set up dummy credentials for testing
        os.environ["AWS_ACCESS_KEY_ID"] = "dummy_access_key"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "dummy_secret_access_key"

        # See the matching comment in AuthenticatorTest.setUp: this avoids a
        # real sts:GetCallerIdentity network call (and the socket leak it
        # can cause on old botocore) on every test in this class.
        patcher = mock.patch(
            "certbot_dns_route53._internal.dns_route53._log_resolved_credentials")
        self.addCleanup(patcher.stop)
        patcher.start()

        self.client = Authenticator(self.config, "route53")

    def tearDown(self):
        # Remove the dummy credentials from env vars
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_find_zone_id_for_domain(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.EXAMPLE_NET_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        assert result == "EXAMPLE"

    def test_find_zone_id_for_domain_pagination(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_COM_ZONE,
                ]
            },
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.FOO_EXAMPLE_COM_ZONE,
                ]
            }
        ]

        result = self.client._find_zone_id_for_domain("foo.example.com")
        assert result == "FOO"

    def test_find_zone_id_for_domain_no_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = []

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_find_zone_id_for_domain_no_correct_results(self):
        self.client.r53.get_paginator = mock.MagicMock()
        self.client.r53.get_paginator().paginate.return_value = [
            {
                "HostedZones": [
                    self.PRIVATE_ZONE,
                    self.EXAMPLE_NET_ZONE,
                ]
            },
        ]

        with pytest.raises(errors.PluginError):
            self.client._find_zone_id_for_domain("foo.example.com")

    def test_change_txt_record(self):
        self.client._find_zone_id_for_domain = mock.MagicMock() # type: ignore [method-assign, unused-ignore]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("FOO", DOMAIN, "foo")

        call_count = self.client.r53.change_resource_record_sets.call_count
        assert call_count == 1

    def test_change_txt_record_delete(self):
        self.client._find_zone_id_for_domain = mock.MagicMock() # type: ignore[ method-assign, unused-ignore]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        validation = "some-value"
        validation_record = {"Value": '"{0}"'.format(validation)}
        self.client._resource_records[DOMAIN] = [validation_record]

        self.client._change_txt_record("DELETE", DOMAIN, validation)

        call_count = self.client.r53.change_resource_record_sets.call_count
        assert call_count == 1
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        assert call_args_batch["Action"] == "DELETE"
        assert call_args_batch["ResourceRecordSet"]["ResourceRecords"] == \
            [validation_record]

    def test_change_txt_record_multirecord(self):
        self.client._find_zone_id_for_domain = mock.MagicMock() # type: ignore [method-assign, unused-ignore]
        self.client._resource_records[DOMAIN] = [
            {"Value": "\"pre-existing-value\""},
            {"Value": "\"pre-existing-value-two\""},
        ]
        self.client.r53.change_resource_record_sets = mock.MagicMock(
            return_value={"ChangeInfo": {"Id": 1}})

        self.client._change_txt_record("DELETE", DOMAIN, "pre-existing-value")

        call_count = self.client.r53.change_resource_record_sets.call_count
        call_args = self.client.r53.change_resource_record_sets.call_args_list[0][1]
        call_args_batch = call_args["ChangeBatch"]["Changes"][0]
        assert call_args_batch["Action"] == "UPSERT"
        assert call_args_batch["ResourceRecordSet"]["ResourceRecords"] == \
            [{"Value": "\"pre-existing-value-two\""}]

        assert call_count == 1

    def test_wait_for_change(self):
        self.client.r53.get_change = mock.MagicMock(
            side_effect=[{"ChangeInfo": {"Status": "PENDING"}},
                         {"ChangeInfo": {"Status": "INSYNC"}}])

        self.client._wait_for_change("1")

        assert self.client.r53.get_change.called


class CredentialsFileTest(unittest.TestCase):
    """--dns-route53-credentials: flat key=value file."""
    # pylint: disable=protected-access

    def setUp(self):
        self.config = mock.MagicMock(route53_credentials=None, route53_awscredentials=None,
                                      route53_awsprofile=None, route53_region=None)

    def _write(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_literal_keys(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_credentials = self._write(
            "aws_access_key_id=AKIAEXAMPLE\naws_secret_access_key=secretexample\n")
        # Real (fake) access key + secret resolve successfully, so this would
        # otherwise trigger a real sts:GetCallerIdentity call. See the
        # comment in AuthenticatorTest.setUp for why that's a problem here.
        with mock.patch(
            "certbot_dns_route53._internal.dns_route53._log_resolved_credentials"
        ):
            auth = Authenticator(self.config, "route53")
        creds = auth.r53._request_signer._credentials
        self.assertEqual(creds.access_key, "AKIAEXAMPLE")

    def test_aws_region_key(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_credentials = self._write(
            "aws_access_key_id=AKIAEXAMPLE\naws_secret_access_key=secretexample\n"
            "aws_region=eu-south-1\n")
        with mock.patch(
            "certbot_dns_route53._internal.dns_route53.boto3.client"
        ) as mock_client:
            Authenticator(self.config, "route53")
            mock_client.assert_any_call(
                "route53", aws_access_key_id="AKIAEXAMPLE",
                aws_secret_access_key="secretexample", aws_session_token=None,
                region_name="eu-south-1")

    def test_missing_file_raises(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_credentials = "/does/not/exist"
        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")

    def test_no_keys_raises(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_credentials = self._write("# no usable keys here\n")
        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")

    def test_multiple_sections_raises(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_credentials = self._write(
            "[default]\naws_access_key_id=AKIAEXAMPLE\naws_secret_access_key=secretexample\n"
            "[other]\naws_access_key_id=AKIAOTHER\naws_secret_access_key=othersecret\n")
        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")


class AwsCredentialsFileTest(unittest.TestCase):
    """--dns-route53-awscredentials: real multi-profile AWS-style file."""
    # pylint: disable=protected-access

    def setUp(self):
        self.config = mock.MagicMock(route53_credentials=None, route53_awscredentials=None,
                                      route53_awsprofile=None, route53_region=None)

    def _write(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_selects_profile(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_awscredentials = self._write(
            "[default]\naws_access_key_id=AKIADEFAULT\naws_secret_access_key=defaultsecret\n"
            "[production]\naws_access_key_id=AKIAPROD\naws_secret_access_key=prodsecret\n")
        self.config.route53_awsprofile = "production"
        # See the comment in AuthenticatorTest.setUp: a resolvable profile
        # here would otherwise trigger a real sts:GetCallerIdentity call.
        with mock.patch(
            "certbot_dns_route53._internal.dns_route53._log_resolved_credentials"
        ):
            auth = Authenticator(self.config, "route53")
        creds = auth.r53._request_signer._credentials
        self.assertEqual(creds.access_key, "AKIAPROD")

    def test_missing_file_raises(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_awscredentials = "/does/not/exist"
        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")

    def test_profile_not_found_raises(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        self.config.route53_awscredentials = self._write(
            "[default]\naws_access_key_id=AKIADEFAULT\naws_secret_access_key=defaultsecret\n")
        self.config.route53_awsprofile = "doesnotexist"
        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")

    def test_both_credential_flags_mutually_exclusive(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        path = self._write("[default]\naws_access_key_id=A\naws_secret_access_key=B\n")
        self.config.route53_credentials = path
        self.config.route53_awscredentials = path
        with self.assertRaises(errors.PluginError):
            Authenticator(self.config, "route53")


class ResolvedCredentialsLoggingTest(unittest.TestCase):
    """_log_resolved_credentials: never logs the access key, and cleans up
    its throwaway STS client without leaking a connection -- regression
    test for a real CI failure (unclosed SSL socket -> ResourceWarning,
    escalated by certbot's own filterwarnings=error into a failure on an
    unrelated test)."""

    def test_access_key_never_logged(self):
        from certbot_dns_route53._internal.dns_route53 import _log_resolved_credentials
        with self.assertLogs("certbot_dns_route53._internal.dns_route53", level="INFO") as ctx:
            _log_resolved_credentials("test source", "AKIASECRETVALUE", "myprofile")
        joined = "\n".join(ctx.output)
        self.assertNotIn("AKIASECRETVALUE", joined)
        self.assertIn('Profile "myprofile"', joined)

    def test_sts_client_cleanup_does_not_leak(self):
        from certbot_dns_route53._internal.dns_route53 import _log_resolved_credentials

        class Leaky:
            def __init__(self):
                self._self_ref = self  # reference cycle, like real botocore/urllib3 objects

            def get_caller_identity(self):
                return {"Arn": "arn:aws:iam::123456789012:user/x", "Account": "123456789012"}

            def __del__(self):
                warnings.warn("unclosed", ResourceWarning)

        escaped: list[sys.UnraisableHookArgs] = []
        old_hook = sys.unraisablehook
        sys.unraisablehook = escaped.append
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", ResourceWarning)  # matches certbot's pytest.ini
                _log_resolved_credentials("test", "AKIATEST", None, sts_client_factory=Leaky)
                gc.collect()
        finally:
            sys.unraisablehook = old_hook
        self.assertEqual(escaped, [])


class LegacyPathTest(unittest.TestCase):
    """Bare --dns-route53 (no credentials file)."""

    def test_profile_not_found_raises_clean_error(self):
        from certbot_dns_route53._internal.dns_route53 import Authenticator
        config = mock.MagicMock(route53_credentials=None, route53_awscredentials=None,
                                 route53_awsprofile="doesnotexist", route53_region=None)
        with tempfile.TemporaryDirectory() as fake_home:
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = fake_home
            try:
                with self.assertRaises(errors.PluginError):
                    Authenticator(config, "route53")
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
