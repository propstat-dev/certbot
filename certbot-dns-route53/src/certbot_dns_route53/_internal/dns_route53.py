"""Certbot Route53 authenticator plugin."""
import collections
import logging
import time
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
from certbot import achallenges
from certbot import errors
from certbot import interfaces
from certbot.achallenges import AnnotatedChallenge
from certbot.compat import os
from certbot.plugins import common

logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "To use certbot-dns-route53, a variety of credential strategies are possible." # pylint: disable=line-too-long
    "Consult the documentation for all options."  # pylint: disable=line-too-long
    "https://certbot-dns-route53.readthedocs.io/en/stable/ ")

# Recognized keys within a --dns-route53-credentials file. Section headers
# (e.g. "[default]") are tolerated but ignored for parsing purposes -- the
# file is treated as a flat set of key=value pairs, so no section header is
# required at all. A file with more than one [section] header alongside
# literal keys is refused outright (see _client_from_flat_credentials_file)
# rather than silently using whichever section came first -- use
# --dns-route53-awscredentials for a file with more than one credential set.
_ACCESS_KEY_KEYS = ("aws_access_key_id",)
_SECRET_KEY_KEYS = ("aws_secret_access_key",)
_SESSION_TOKEN_KEYS = ("aws_session_token", "aws_security_token")
_PROFILE_KEYS = ("certbot_dns_route53_profile", "dns_route53_profile")
_REGION_KEYS = ("certbot_dns_route53_region", "dns_route53_region")


class _FlatFileFields(NamedTuple):
    """Fields recognized in a flat key=value credentials file. Populated
    by _parse_flat_key_value_file and consumed by both
    --dns-route53-credentials (which needs every field) and the
    dns_route53_profile/dns_route53_region inline-override scan used by
    --dns-route53-awscredentials (which only needs profile/region)."""
    access_key: Optional[str]
    secret_key: Optional[str]
    session_token: Optional[str]
    profile: Optional[str]
    region: Optional[str]
    section_count: int


def _parse_flat_key_value_file(creds_file: str) -> _FlatFileFields:
    """Single-pass, line-by-line parse of creds_file as a flat set of
    key=value pairs. [section] header lines, if present, are tolerated but
    ignored -- the whole file is read as one flat namespace, so no section
    header is required. NOTE: because sections are ignored, a file with
    more than one real credential set under different [section]s is not
    safely supported here -- use --dns-route53-awscredentials for that
    instead. Comments (#, ;) and blank lines are skipped. For each field,
    the first matching key encountered wins, checked across all of that
    field's recognized aliases in file line order -- e.g. if both
    dns_route53_profile and its certbot_-prefixed alias appear, whichever
    comes first in the file wins, regardless of alias.

    Raises whatever open()/iteration raises (OSError on a missing/unreadable
    file); callers decide how strictly to treat that. section_count is the
    number of [section]-style header lines seen, so --dns-route53-credentials
    can detect and refuse a file that looks like it actually holds more than
    one profile, rather than silently using whichever key came first."""
    access_key = secret_key = session_token = profile = region = None
    section_count = 0
    with open(creds_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";") \
                    or line.startswith("["):
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
    """self.conf(...)/os.environ.get(...) can hand back non-str values;
    normalize anything that isn't a real string to None."""
    return value if isinstance(value, str) else None


# Cleared (not merely left alone) for the duration of
# --dns-route53-awscredentials's credential resolution -- each of these
# can otherwise silently outrank or substitute for the file the caller
# explicitly pointed us at. See _client_from_aws_credentials_file.
_ISOLATED_AWS_ENV_VARS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
)


@contextmanager
def _scoped_env(overrides: dict[str, Optional[str]]) -> Iterator[None]:
    """Temporarily apply env var overrides (None means unset that var),
    restoring every previous value on exit regardless of how the block
    exits."""
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
    """Log whether AWS credentials were resolved, and via what source/
    profile, so "which profile/account created this certificate" is
    answerable from the log file afterward. Never logs the access key
    (or any other credential material) itself.

    If sts_client_factory is given, also makes a best-effort
    sts:GetCallerIdentity call using the already-resolved credentials, to
    log a verified ARN/account rather than just "which file/profile we
    pointed at". This needs no IAM permissions at all -- confirmed via
    AWS's own docs: GetCallerIdentity still succeeds even under an
    explicit deny policy, since the same information is returned either
    way. It's still wrapped in a broad except: verified empirically that
    a blocked network path (e.g. a restrictive corporate proxy) can raise
    botocore.parsers.ResponseParserError, which is not a botocore/AWS SDK
    exception subclass at all -- so nothing narrower is guaranteed to
    catch every way this optional enrichment step could fail, and it must
    never be able to break actual certificate issuance."""
    profile_suffix = f' (Profile "{profile}")' if profile else ""
    if not access_key:
        logger.info("certbot-dns-route53: No AWS credentials found via %s%s",
                     source, profile_suffix)
        return

    identity_suffix = ""
    if sts_client_factory is not None:
        try:
            identity = sts_client_factory().get_caller_identity()
            identity_suffix = (
                f' -- verified identity: {identity.get("Arn", "<unknown>")} '
                f'(account {identity.get("Account", "<unknown>")})')
        except Exception as e:  # pylint: disable=broad-except
            logger.debug(
                "certbot-dns-route53: sts:GetCallerIdentity check failed "
                "(non-fatal, continuing without it): %s", e)

    logger.info("certbot-dns-route53: Found credentials via %s%s%s",
                source, profile_suffix, identity_suffix)


class Authenticator(common.Plugin, interfaces.Authenticator):
    """DNS Authenticator for Amazon AWS Route53.

    This authenticator uses the AWS Route53 API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using AWS Route53 for '
                   'DNS).')
    ttl = 10

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Extract values, strictly ensuring they are strings or fallback to environment variables
        profile = _str_or_none(
            self.conf("profile") or os.environ.get("CERTBOT_DNS_ROUTE53_PROFILE"))
        region = _str_or_none(self.conf("region") or os.environ.get("CERTBOT_DNS_ROUTE53_REGION"))
        creds_file = _str_or_none(self.conf("credentials"))
        aws_creds_file = _str_or_none(self.conf("awscredentials"))

        if creds_file and aws_creds_file:
            raise errors.PluginError(
                "Only one of --dns-route53-credentials or --dns-route53-awscredentials "
                "may be specified."
            )

        if aws_creds_file:
            self.r53 = self._client_from_aws_credentials_file(aws_creds_file, profile, region)
        elif creds_file:
            self.r53 = self._client_from_flat_credentials_file(creds_file, profile, region)
        else:
            # Standard legacy code path: environment variables, ~/.aws/credentials,
            # AWS_CONFIG_FILE, or an explicit --dns-route53-profile/--dns-route53-region
            # against that same standard chain. Always build an explicit
            # boto3.Session() (fully public API) rather than the bare
            # boto3.client("route53") convenience function, even when no
            # profile/region is given: the convenience function relies on
            # boto3's module-global DEFAULT_SESSION, which isn't clearly
            # public API (even boto3-focused write-ups avoid depending on
            # it), so there'd be no safe way to read back which identity it
            # resolved to for logging. The cost is that each lineage
            # re-resolves credentials instead of reusing one cached
            # module-global session across a certbot renew run -- a minor,
            # undocumented performance detail, not a correctness one.
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
        self._resource_records: collections.defaultdict[str, list[dict[str, str]]] = \
            collections.defaultdict(list)
        self._resource_records_change_ids: dict[str, str] = {}

    @staticmethod
    def _scan_inline_overrides(creds_file: str, profile: Optional[str],
                                region: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        """Scan creds_file for dns_route53_profile/dns_route53_region
        overrides via _parse_flat_key_value_file, regardless of what
        [section] (if any) they sit under. An already-set profile/region
        (from CLI or env) is never overridden. Read failures are tolerated
        here rather than raised -- --dns-route53-awscredentials's own
        credential resolution gets the chance to raise its own, clearer
        error afterward if the file turns out to be genuinely unusable."""
        try:
            fields = _parse_flat_key_value_file(creds_file)
        except (OSError, ValueError) as e:
            logger.debug("Failed parsing inline overrides in %s: %s", creds_file, e)
            return profile, region
        return (profile if profile is not None else fields.profile,
                region if region is not None else fields.region)

    def _client_from_flat_credentials_file(self, creds_file: str, profile: Optional[str],
                                            region: Optional[str]) -> Any:
        """--dns-route53-credentials: a flat key=value file. A single
        [section] header, if present, is skipped but not tracked -- the
        whole file is read as one namespace, so no section header is
        required. Only use this for a file holding a single credential
        set: if more than one [section] header is present alongside
        literal keys, that's refused outright rather than silently using
        whichever section's keys happened to appear first -- --dns-route53-profile
        can't select between them here, since profile is only ever
        consulted as a fallback when no literal keys are found at all."""
        if not os.path.exists(creds_file):
            raise errors.PluginError(f"Credentials file {creds_file} does not exist")

        try:
            fields = _parse_flat_key_value_file(creds_file)
        except OSError as e:
            raise errors.PluginError(f"Error reading credentials file {creds_file}: {e}")

        if profile is None:
            profile = fields.profile
        if region is None:
            region = fields.region

        if fields.access_key and fields.secret_key:
            if fields.section_count > 1:
                raise errors.PluginError(
                    f"Credentials file {creds_file} contains {fields.section_count} "
                    "[section] headers alongside literal AWS keys. "
                    "--dns-route53-credentials only supports a single flat credential "
                    "set -- any keys beyond the first section would be silently "
                    "ignored, and --dns-route53-profile cannot select between "
                    "sections here. Use --dns-route53-awscredentials instead for a "
                    "file with more than one profile."
                )
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
        elif profile:
            # No literal keys in the file -- fall back to a named profile
            # from the standard AWS config/credentials chain.
            try:
                session = boto3.Session(profile_name=profile, region_name=region)
                creds = session.get_credentials()
            except ProfileNotFound as e:
                raise errors.PluginError(f"Couldn't load AWS credentials: {e}")
            _log_resolved_credentials(
                f"--dns-route53-credentials {creds_file} (profile fallback, "
                "no literal keys in file)",
                creds.access_key if creds else None, profile,
                sts_client_factory=lambda: session.client("sts"))
            return session.client("route53")
        else:
            raise errors.PluginError(
                f"Credentials file {creds_file} must contain aws_access_key_id and "
                "aws_secret_access_key, or a profile name to use from your AWS config."
            )

    def _client_from_aws_credentials_file(self, creds_file: str, profile: Optional[str],
                                           region: Optional[str]) -> Any:
        """--dns-route53-awscredentials: a genuine, section-aware AWS-style
        credentials file (like ~/.aws/credentials). profile selects which
        [section] supplies the actual keys.

        Resolution is delegated to boto3, redirected at creds_file via
        AWS_SHARED_CREDENTIALS_FILE, but otherwise fully isolated from the
        ambient process environment for the duration of this call --
        matching the original SharedCredentialProvider-only behavior.
        Without this isolation, ambient AWS_ACCESS_KEY_ID/AWS_PROFILE/etc.
        can silently outrank creds_file, a same-named role_arn in
        ~/.aws/config can trigger an unwanted AssumeRole, and an
        unresolvable profile falls through to a real network call to the
        EC2 instance-metadata service (169.254.169.254) -- security-
        relevant on the EC2/ECS/EKS infrastructure this plugin commonly
        runs on. See _ISOLATED_AWS_ENV_VARS for the full set of env vars
        this clears. --dns-route53-credentials (the flat-file path) is
        already immune to all of this, since it builds its client from
        explicitly-extracted keys rather than delegating to boto3.

        The isolation is scoped to just this call, so it's safe across
        certbot renew's sequential per-lineage processing."""
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
                    + (f" using profile '{profile}'" if profile else
                       " using the 'default' profile")
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
        add('credentials', help='Load AWS credentials from a simple key=value file '
                                 '(no [section] header required; single credential set only).')
        add('awscredentials', help='Load AWS credentials from a standard AWS-style '
                                    'credentials file with [profile] sections (supports '
                                    'multiple credential sets, selected via --dns-route53-profile).') # pylint: disable=line-too-long
        add('profile', help='AWS profile name to use.')
        add('region', help='AWS region name to use.')

    def auth_hint(self, failed_achalls: list[achallenges.AnnotatedChallenge]) -> str:
        return (
            'The Certificate Authority failed to verify the DNS TXT records created by '
            '--dns-route53. Ensure the above domains have their DNS hosted by AWS Route53.'
        )

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
            raise errors.PluginError(
                "Unable to find a Route53 hosted zone for {0}".format(domain)
            )

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
                # Some ACME CAs return identical challenge values for apex and
                # wildcard on the same domain. Route53 rejects duplicate resource
                # records, so return the previous change ID without re-submitting.
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
        raise errors.PluginError(
            "Timed out waiting for Route53 change. Current status: %s" %
            response["ChangeInfo"]["Status"])


class HiddenAuthenticator(Authenticator):
    """A hidden shim around certbot-dns-route53 for backwards compatibility."""

    hidden = True
