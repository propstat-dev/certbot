"""Certbot Route53 authenticator plugin."""
import collections
import gc
import logging
import time
import warnings
from contextlib import contextmanager
from typing import Any
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import NamedTuple
from typing import Optional
from typing import cast

import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import NoCredentialsError
from botocore.exceptions import ProfileNotFound

from acme import challenges
from certbot import achallenges, errors, interfaces
from certbot.achallenges import AnnotatedChallenge
from certbot.compat import os
from certbot.plugins import common

logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "To use certbot-dns-route53, a variety of credential strategies are possible. "
    "Consult the documentation for all options. "
    "https://certbot-dns-route53.readthedocs.io/en/stable/ "
)

_ACCESS_KEY_KEYS = ("aws_access_key_id",)
_SECRET_KEY_KEYS = ("aws_secret_access_key",)
_SESSION_TOKEN_KEYS = ("aws_session_token", "aws_security_token")
_PROFILE_KEYS = ("certbot_dns_route53_awsprofile", "dns_route53_awsprofile")
_REGION_KEYS = ("aws_region",)


class _FlatFileFields(NamedTuple):
    access_key: Optional[str]
    secret_key: Optional[str]
    session_token: Optional[str]
    profile: Optional[str]
    region: Optional[str]
    section_count: int


def _parse_flat_key_value_file(creds_file: str) -> _FlatFileFields:
    access_key = secret_key = session_token = profile = region = None
    section_count = 0
    with open(creds_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";") or line.startswith("["):
                if line.startswith("[") and line.endswith("]"):
                    section_count += 1
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip().lower()
            v = v.strip().strip('"').strip("'")

            if k in _ACCESS_KEY_KEYS and access_key is None:
                access_key = v
            elif k in _SECRET_KEY_KEYS and secret_key is None:
                secret_key = v
            elif k in _SESSION_TOKEN_KEYS and session_token is None:
                session_token = v
            elif k in _PROFILE_KEYS and profile is None:
                profile = v
            elif k in _REGION_KEYS and region is None:
                region = v
    return _FlatFileFields(access_key, secret_key, session_token, profile, region, section_count)


def _str_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


_ISOLATED_AWS_ENV_VARS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
)


@contextmanager
def _scoped_env(overrides: dict[str, Optional[str]]) -> Iterator[None]:
    old_values = {var: os.environ.get(var) for var in overrides}
    for var, value in overrides.items():
        if value is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = value
    try:
        yield
    finally:
        for var, old in old_values.items():
            if old is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = old


def _log_resolved_credentials(source: str, access_key: Optional[str],
                               profile: Optional[str],
                               sts_client_factory: Optional[Callable[[], Any]] = None) -> None:
    profile_suffix = f' (Profile "{profile}")' if profile else ""
    if not access_key:
        logger.info("certbot-dns-route53: No AWS credentials found via %s%s", source, profile_suffix)
        return

    identity_suffix = ""
    if sts_client_factory is not None:
        sts_client = None
        try:
            sts_client = sts_client_factory()
            identity = sts_client.get_caller_identity()
            identity_suffix = (
                f' -- verified identity: {identity.get("Arn", "<unknown>")} '
                f'(account {identity.get("Account", "<unknown>")})')
        except Exception as e:  # pylint: disable=broad-except
            logger.debug("certbot-dns-route53: sts:GetCallerIdentity check failed: %s", e)
        finally:
            # Close the throwaway client explicitly -- left alone, its
            # connection is only released whenever garbage collection gets
            # to it, which can happen during unrelated code and trips
            # certbot's own test suite (filterwarnings = error). close()
            # isn't on every supported botocore version (confirmed absent
            # on 1.23.34), so force finalization here too, with the
            # resulting warning suppressed since we're handling it on purpose.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                if sts_client is not None and hasattr(sts_client, "close"):
                    try:
                        sts_client.close()
                    except Exception:  # pylint: disable=broad-except
                        pass
                del sts_client
                gc.collect()

    logger.info("certbot-dns-route53: Found credentials via %s%s%s", source, profile_suffix, identity_suffix)


class Authenticator(common.Plugin, interfaces.Authenticator):
    """DNS Authenticator for Amazon AWS Route53."""

    description = 'Obtain certificates using a DNS TXT record (if you are using AWS Route53 for DNS).'
    ttl = 10

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        profile = _str_or_none(self.conf("awsprofile") or os.environ.get("CERTBOT_DNS_ROUTE53_AWSPROFILE"))
        region = _str_or_none(self.conf("region") or os.environ.get("CERTBOT_DNS_ROUTE53_REGION"))
        creds_file = _str_or_none(self.conf("credentials"))
        aws_creds_file = _str_or_none(self.conf("awscredentials"))

        if creds_file and aws_creds_file:
            raise errors.PluginError(
                "Only one of --dns-route53-credentials or --dns-route53-awscredentials may be specified."
            )

        if aws_creds_file:
            self.r53 = self._client_from_aws_credentials_file(aws_creds_file, profile, region)
        elif creds_file:
            self.r53 = self._client_from_flat_credentials_file(creds_file, region)
        else:
            try:
                session = boto3.Session(profile_name=profile, region_name=region)
                creds = session.get_credentials()
            except ProfileNotFound as e:
                raise errors.PluginError(f"Couldn't load AWS credentials: {e}")
            _log_resolved_credentials(
                "the standard AWS credential chain",
                creds.access_key if creds else None, profile,
                sts_client_factory=lambda: session.client("sts"))
            self.r53 = session.client("route53")

        self._attempt_cleanup = False
        self._resource_records: collections.defaultdict[str, list[dict[str, str]]] = collections.defaultdict(list)
        self._resource_records_change_ids: dict[str, str] = {}

    @staticmethod
    def _scan_inline_overrides(creds_file: str, profile: Optional[str],
                                region: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        try:
            fields = _parse_flat_key_value_file(creds_file)
        except (OSError, ValueError) as e:
            logger.debug("Failed parsing inline overrides in %s: %s", creds_file, e)
            return profile, region
        return (profile if profile is not None else fields.profile,
                region if region is not None else fields.region)

    def _client_from_flat_credentials_file(self, creds_file: str, region: Optional[str]) -> Any:
        if not os.path.exists(creds_file):
            raise errors.PluginError(f"Credentials file {creds_file} does not exist")

        try:
            fields = _parse_flat_key_value_file(creds_file)
        except OSError as e:
            raise errors.PluginError(f"Error reading credentials file {creds_file}: {e}")

        if not fields.access_key or not fields.secret_key:
            raise errors.PluginError(
                f"Credentials file {creds_file} must contain aws_access_key_id and aws_secret_access_key."
            )

        if fields.section_count > 1:
            raise errors.PluginError(f"Credentials file {creds_file} cannot contain multiple sections.")

        if fields.region and region is None:
            region = fields.region

        _log_resolved_credentials(
            f"--dns-route53-credentials {creds_file}",
            fields.access_key, None,
            sts_client_factory=lambda: boto3.client(
                "sts",
                aws_access_key_id=fields.access_key,
                aws_secret_access_key=fields.secret_key,
                aws_session_token=fields.session_token,
            ))
        return boto3.client(
            "route53",
            aws_access_key_id=fields.access_key,
            aws_secret_access_key=fields.secret_key,
            aws_session_token=fields.session_token,
            region_name=region,
        )

    def _client_from_aws_credentials_file(self, creds_file: str, profile: Optional[str],
                                           region: Optional[str]) -> Any:
        if not os.path.exists(creds_file):
            raise errors.PluginError(f"Credentials file {creds_file} does not exist")

        profile, region = self._scan_inline_overrides(creds_file, profile, region)

        overrides: dict[str, Optional[str]] = dict.fromkeys(_ISOLATED_AWS_ENV_VARS)
        overrides["AWS_SHARED_CREDENTIALS_FILE"] = creds_file
        overrides["AWS_CONFIG_FILE"] = os.devnull
        overrides["AWS_EC2_METADATA_DISABLED"] = "true"

        with _scoped_env(overrides):
            try:
                session = boto3.Session(profile_name=profile, region_name=region)
                creds = session.get_credentials()
            except ProfileNotFound:
                creds = None

            if creds is None:
                raise errors.PluginError(
                    f"Couldn't load AWS credentials from {creds_file}"
                    + (f" using profile '{profile}'" if profile else " using the 'default' profile")
                )
            _log_resolved_credentials(
                f"--dns-route53-awscredentials {creds_file}",
                creds.access_key, profile,
                sts_client_factory=lambda: session.client("sts"))
            return session.client("route53")

    def more_info(self) -> str:
        return "Solve a DNS01 challenge using AWS Route53"

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        super().add_parser_arguments(add)
        add('credentials', help='Load AWS credentials from a simple flat key=value file.')
        add('awscredentials', help='Load AWS credentials from a standard AWS-style credentials file.')
        add('awsprofile', help='AWS profile name to use.')
        add('region', help='AWS region name to use.')

    def auth_hint(self, failed_achalls: list[achallenges.AnnotatedChallenge]) -> str:
        return 'The Certificate Authority failed to verify the DNS TXT records created by --dns-route53.'

    def prepare(self) -> None:
        pass

    def get_chall_pref(self, unused_identifier: str) -> Iterable[type[challenges.Challenge]]:
        return [challenges.DNS01]

    def perform(self, achalls: list[AnnotatedChallenge]) -> list[challenges.ChallengeResponse]:
        self._attempt_cleanup = True
        try:
            change_ids = [
                self._change_txt_record("UPSERT",
                  achall.validation_domain_name(achall.identifier.value),
                  achall.validation(achall.account_key))
                for achall in achalls
            ]
            for change_id in change_ids:
                self._wait_for_change(change_id)
        except (NoCredentialsError, ClientError) as e:
            logger.debug('Encountered error during perform: %s', e, exc_info=True)
            raise errors.PluginError("\n".join([str(e), INSTRUCTIONS]))
        return [achall.response(achall.account_key) for achall in achalls]

    def cleanup(self, achalls: list[achallenges.AnnotatedChallenge]) -> None:
        if self._attempt_cleanup:
            for achall in achalls:
                domain = achall.identifier.value
                validation_domain_name = achall.validation_domain_name(domain)
                validation = achall.validation(achall.account_key)
                self._cleanup(validation_domain_name, validation)

    def _cleanup(self, validation_name: str, validation: str) -> None:
        try:
            self._change_txt_record("DELETE", validation_name, validation)
        except (NoCredentialsError, ClientError) as e:
            logger.debug('Encountered error during cleanup: %s', e, exc_info=True)

    def _find_zone_id_for_domain(self, domain: str) -> str:
        paginator = self.r53.get_paginator("list_hosted_zones")
        zones: list[tuple[str, str]] = []
        target_labels = domain.rstrip(".").split(".")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Config"]["PrivateZone"]:
                    continue
                candidate_labels = zone["Name"].rstrip(".").split(".")
                if candidate_labels == target_labels[-len(candidate_labels):]:
                    zones.append((zone["Name"], zone["Id"]))
        if not zones:
            raise errors.PluginError("Unable to find a Route53 hosted zone for {0}".format(domain))
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action: str, validation_domain_name: str, validation: str) -> str:
        zone_id = self._find_zone_id_for_domain(validation_domain_name)
        rrecords = self._resource_records[validation_domain_name]
        challenge = {"Value": '"{0}"'.format(validation)}
        if action == "DELETE":
            rrecords.remove(challenge)
            if rrecords:
                action = "UPSERT"
            else:
                rrecords = [challenge]
        else:
            if challenge in rrecords:
                return self._resource_records_change_ids[validation_domain_name]
            rrecords.append(challenge)

        response = self.r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "certbot-dns-route53 certificate validation " + action,
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": validation_domain_name,
                            "Type": "TXT",
                            "TTL": self.ttl,
                            "ResourceRecords": rrecords,
                        }
                    }
                ]
            }
        )
        change_id = cast(str, response["ChangeInfo"]["Id"])
        self._resource_records_change_ids[validation_domain_name] = change_id
        return change_id

    def _wait_for_change(self, change_id: str) -> None:
        for unused_n in range(0, 120):
            response = self.r53.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)
        raise errors.PluginError("Timed out waiting for Route53 change. Current status: %s" % response["ChangeInfo"]["Status"])


class HiddenAuthenticator(Authenticator):
    """A hidden shim around certbot-dns-route53 for backwards compatibility."""

    hidden = True
