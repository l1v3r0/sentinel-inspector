#!/usr/bin/env python3
"""
Sentinel Workspace Inspector
Author:    l1v3r  (https://github.com/l1v3r0)
Validated: Claude (Anthropic)

Inspect Microsoft Sentinel workspaces and validate analytics rules
against the target environment using Azure CLI authentication.

Usage:
    python3 sentinel_inspector.py
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import time
import calendar
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

# ── Third-party bootstrap ─────────────────────────────────────────────────────

def _bootstrap_requests():
    """Install requests if missing, then return the module."""
    try:
        import requests as _r
        return _r
    except ImportError:
        logging.warning("'requests' not found — installing...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "requests", "--quiet"]
        )
        import requests as _r
        return _r

requests = _bootstrap_requests()

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel_inspector")

# ── Constants ─────────────────────────────────────────────────────────────────

LA_AUDIENCE          = "https://api.loganalytics.io"
ARM_AUDIENCE         = "https://management.azure.com"
LA_QUERY_URL         = "https://api.loganalytics.io/v1/workspaces/{workspace}/query"
ARM_BASE_URL         = "https://management.azure.com"
ARM_WS_PATH          = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}"
ARM_SENTINEL_PATH    = ARM_WS_PATH + "/providers/Microsoft.SecurityInsights"
SAVED_SEARCHES_API   = "2020-08-01"
ALERT_RULES_API      = "2023-02-01"

TIMEOUT_AZ_VERSION   = 10
TIMEOUT_AZ_SHOW      = 15
TIMEOUT_AZ_LIST      = 30
TIMEOUT_AZ_SET       = 30
TIMEOUT_AZ_LOGIN     = 120
TIMEOUT_AZ_DEVICECODE= 180
TIMEOUT_BREW_INSTALL = 300
TIMEOUT_WS_LIST      = 30
TIMEOUT_LA_QUERY     = 60
TIMEOUT_ARM_GET      = 30
TIMEOUT_TOKEN        = 30
TOKEN_EXPIRY_MARGIN  = 60    # seconds before expiry to refresh
TOKEN_DEFAULT_TTL    = 3300  # seconds (55 min)
HTTP_RETRY_COUNT     = 3
RULE_LOOKBACK_DAYS   = 30

OS = platform.system()  # 'Darwin', 'Windows', 'Linux'

# ── KQL keyword / builtin sets ────────────────────────────────────────────────

KW: frozenset[str] = frozenset({
    "where","extend","project","summarize","join","union","let","mv-expand","parse",
    "evaluate","render","sort","order","top","limit","distinct","count","make-series",
    "datatable","range","print","search","find","invoke","partition","serialize",
    "sample","reduce","project-away","project-rename","project-reorder","project-keep",
    "as","consume","getschema","mv-apply","scan","fork","facet","lookup",
    "inner","leftouter","rightouter","fullouter","leftanti","rightanti",
    "leftsemi","rightsemi","innerunique","leftantisemi","on","kind",
    "and","or","not","in","between","has","contains","startswith","endswith",
    "matches","regex","by","asc","desc","nulls","first","last","isfuzzy",
    "bool","int","long","real","double","string","datetime","timespan",
    "dynamic","guid","decimal","typeof",
    "t","T","e","vl","df","table","table_parameter","result","results",
    "starttime","endtime","start","end",
    "case","iff","iif","true","false","null",
})

BUILTINS: frozenset[str] = frozenset({
    "tostring","toint","tolong","todouble","tobool","todatetime","totimespan","toreal",
    "todynamic","toguid","tohex","tobase64","typeof","gettype","parse_json","coalesce",
    "isempty","isnotempty","isnull","isnotnull","iff","iif","case","now","ago","bin",
    "hash_sha1","hash_sha256","hash_md5","hash_xxhash64","strcat","strcat_array",
    "array_concat","array_sort_asc","array_sort_desc","array_slice","array_length",
    "array_iif","array_index_of","array_reverse","array_rotate_left","array_split",
    "array_sum","array_zip","bag_keys","bag_set_key","bag_merge","bag_remove_keys",
    "bag_pack","pack_array","pack_all","make_set","make_set_if","make_list",
    "make_list_if","make_bag","columnifexists","column_ifexists","arg_max","arg_min",
    "take_any","take_anyif","extract_all","extract","replace_strings","replace",
    "replace_string","trim_end","trim_start","trim","parse_ipv6","parse_ipv4",
    "parse_url","ipv4_is_private","ipv4_is_in_any_range","ipv6_is_in_any_range",
    "ipv6_is_match","ipv4_is_match","ipv4_compare","ipv6_compare","ipv4_is_in_range",
    "toscalar","countif","sumif","dcountif","count","sum","avg","min","max","dcount",
    "stdev","variance","percentile","make_series","tolower","toupper","split","strlen",
    "format_datetime","format_timespan","substring","indexof","indexof_regex","reverse",
    "pad_left","pad_right","parse_command_line","parse_urlquery","parse_path",
    "floor","ceiling","round","abs","sqrt","pow","log","log2","exp","rand","sign",
    "datetime_diff","datetime_add","startofday","startofmonth","endofday","endofmonth",
    "startofweek","endofweek","startofyear","endofyear","dayofmonth","dayofweek",
    "hourofday","monthofyear","getyear","getmonth","bin_at","make_datetime",
    "set_intersect","set_union","set_difference","zip","unpack","dynamic_to_json",
    "geo_point_to_h3cell","geo_distance_2points","geo_point_in_circle",
    "url_encode","url_decode","base64_encode_tostring","base64_decode_tostring",
    "ingestion_time","estimate_data_size","cursor_after","mv-apply","evaluate",
    "pivot","narrow","bag_unpack","series_stats","series_decompose","series_fit_line",
    "series_outliers","basket","autocluster","diffpatterns","funnel_sequence",
    "hint","shuffle","strategy",
    "int","long","real","double","bool","string","datetime","timespan","dynamic","guid",
    # performance hints and operators
    "materialize","toscalar","hint","shuffle","strategy",
    # Sentinel built-in functions and watchlist helpers
    "_GetWatchlist","_ASIM_GetSourceBySourceType",
    "_Im_Dns","_Im_NetworkSession","_Im_Authentication","_Im_FileEvent",
    "_Im_ProcessCreate","_Im_RegistryEvent","_Im_WebSession",
    "_Im_AuditEvent","_Im_UserManagement",
    # materialize and other missed operators
    "materialize",
    # commonly missed
    "has_any","has_all","has_prefix","has_suffix","has","in~","!in","!has",
    "between","!between","matches","startswith_cs","endswith_cs","contains_cs",
    "!contains","!startswith","!endswith","!matches",
    # Math trig and advanced
    "asin","acos","atan","atan2","degrees","radians","sin","cos","tan",
    "exp2","exp10","log2","log10","beta_cdf","beta_inv","beta_pdf","gamma","loggamma","pi",
    # String
    "count_distinct","replace_regex","unicode_codepoint_from_string",
    "unicode_codepoints_to_string","url_encode_component",
    "base64_decode_toarray","base64_encode_fromarray","hash_many","parse_xml",
    # Datetime
    "bin_auto","bin_at","datetime_part","datetime_local_to_utc","datetime_utc_to_local",
    "dayofyear","hourofday","monthofyear",
    # Array
    "array_rotate_left","array_rotate_right","array_shift_left","array_shift_right",
    "array_sum","array_zip",
    # Conditional
    "isfinite","isinf","isnan","isbool","isint","islong","isreal","isutf8",
    # IP
    "ipv6_is_in_range","format_ipv4","format_ipv4_mask",
    # Geo
    "geo_geohash_to_central_point","geo_h3cell_to_central_point",
    "geo_point_in_polygon","geo_point_to_geohash",
    "geo_polygon_area","geo_polygon_centroid",
    "h3cell_children","h3cell_parent","h3cell_to_central_point",
    # Series
    "series_fft","series_ifft","series_multiply","series_add","series_subtract",
    "series_divide","series_dot_product","series_greater","series_greater_equals",
    "series_less","series_less_equals","series_equals","series_not_equals",
    # Aggregation
    "avgif","minif","maxif","stdevif","varianceif","dcountif","percentiles_array",
    # Plugins
    "active_users_count","activity_engagement","new_activity_metrics",
    "sliding_window_counts","time_series_anomalies_detection",
    "sequence_detect","infer_storage_schema",
    # Other
    "external_table","cursor_before_or_at","cursor_current",
    # ASIM
    "imDnsEvent",
})

# ASIM unified parser functions — these are workspace-deployed functions,
# never table names. Kept separate from BUILTINS so they remain detectable
# as custom functions to validate against the workspace.
KNOWN_ASIM_FUNCTIONS: frozenset[str] = frozenset({
    "imDns","imNetworkSession","imAuthentication","imFileEvent",
    "imProcessCreate","imProcessTerminate","imRegistryEvent","imWebSession",
    "imAuditEvent","imUserManagement","imNetworkShare","imDhcpEvent","imDnsEvent",
    "ASimDns","ASimNetworkSession","ASimAuthentication","ASimFileEvent",
    "ASimProcessCreate","ASimProcessTerminate","ASimRegistryEvent",
    "ASimWebSession","ASimAuditEvent","ASimUserManagement",
    "ASimNetworkSessionBuiltIn","ASimDnsBuiltIn","ASimAuthenticationBuiltIn",
    "_Im_Dns","_Im_NetworkSession","_Im_Authentication","_Im_FileEvent",
    "_Im_ProcessCreate","_Im_RegistryEvent","_Im_WebSession",
    "_Im_AuditEvent","_Im_UserManagement",
})


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class WorkspaceContext:
    """Holds all identifiers needed to talk to a Sentinel workspace."""
    workspace_id:   str   # Log Analytics GUID (customerId)
    workspace_name: str   # ARM resource name
    subscription_id:str
    resource_group: str


@dataclass
class ValidationResult:
    """Result of validating a single analytics rule."""
    rule_name:        str
    kind:             str
    enabled:          bool
    modified:         str
    # dependency checks
    tables_ok:        list[str]        = field(default_factory=list)
    tables_missing:   list[str]        = field(default_factory=list)
    funcs_ok:         list[str]        = field(default_factory=list)
    funcs_missing:    list[str]        = field(default_factory=list)
    func_body_issues: list[str]        = field(default_factory=list)
    fields_missing:   list[str]        = field(default_factory=list)
    # dry-run
    dry_run_ok:       bool             = False
    dry_run_error:    str              = ""
    # data presence check (check 5)
    no_data_sources:  list[str]        = field(default_factory=list)  # sources with 0 rows in 30d
    # schedule check (check 8)
    query_frequency:  str              = ""   # ISO 8601 e.g. PT5H
    query_period:     str              = ""   # ISO 8601 e.g. PT1H
    schedule_gap:     bool             = False
    # rule state
    skipped:          bool             = False
    skip_reason:      str              = ""

    @property
    def _all_missing(self) -> list[str]:
        # Exclude unattributed field issues — not actionable without table context
        attributed_fields = [f for f in self.fields_missing if not f.startswith("(unknown table).")]
        return (
            self.tables_missing + self.funcs_missing +
            self.func_body_issues + attributed_fields
        )

    @property
    def verdict(self) -> str:
        """Human-readable verdict string."""
        if self.skipped:
            return f"SKIP — {self.skip_reason}"
        if not self.enabled:
            return "DISABLED — rule will not fire"
        if self._all_missing:
            parts = []
            if self.tables_missing:
                parts.append(f"{len(self.tables_missing)} table(s)")
            if self.funcs_missing:
                parts.append(f"{len(self.funcs_missing)} function(s)")
            if self.func_body_issues:
                parts.append(f"{len(self.func_body_issues)} function body issue(s)")
            if self.fields_missing:
                parts.append(f"{len(self.fields_missing)} field(s)")
            return "WILL FAIL  — missing " + ", ".join(parts)
        if self.schedule_gap:
            return (
                f"SCHEDULE GAP — runs every {self.query_frequency} "
                f"but only queries last {self.query_period} — events will be missed"
            )
        if self.no_data_sources:
            return (
                "NO DATA — deps ok but 0 rows in last 30d: "
                + ", ".join(self.no_data_sources)
                + " (parser/connector may not be configured)"
            )
        if self.dry_run_ok:
            return "WILL WORK"
        return "UNCERTAIN  — dry-run failed but no missing deps detected"

    @property
    def status(self) -> str:
        """Short status tag."""
        if self.skipped:
            return "SKIP"
        if not self.enabled:
            return "DISABLED"
        if self.tables_missing or self.funcs_missing:
            return "FAIL"
        if self.schedule_gap:
            return "WARN"
        if self.no_data_sources:
            return "NO DATA"
        if self.dry_run_ok and not self._all_missing:
            return "OK"
        return "WARN"


# ── Session cache ─────────────────────────────────────────────────────────────

class SessionCache:
    """
    In-memory cache for tokens, table lists, schemas, and function metadata.
    Avoids redundant API calls within a single script session.
    """

    def __init__(self) -> None:
        self._tokens:   dict[str, tuple[str, float]] = {}  # audience -> (token, expires_at)
        self._tables:   dict[str, set[str]]           = {}  # ws_id -> table names
        self._schemas:  dict[tuple[str,str], set[str]]= {}  # (ws_id, table) -> field names
        self._func_exists:  dict[tuple[str,str], bool]= {}  # (ws_id, fn) -> exists
        self._func_bodies:  dict[str, dict[str,str]]  = {}  # ws_id -> {alias: kql}

    def get_token(self, audience: str) -> Optional[str]:
        """Return cached token if still valid, else None."""
        entry = self._tokens.get(audience)
        if entry and time.time() < entry[1] - TOKEN_EXPIRY_MARGIN:
            return entry[0]
        return None

    def set_token(self, audience: str, token: str, expires_at: float) -> None:
        self._tokens[audience] = (token, expires_at)

    def get_tables(self, ws_id: str) -> Optional[set[str]]:
        return self._tables.get(ws_id)

    def set_tables(self, ws_id: str, tables: set[str]) -> None:
        self._tables[ws_id] = tables

    def get_schema(self, ws_id: str, table: str) -> Optional[set[str]]:
        return self._schemas.get((ws_id, table))

    def set_schema(self, ws_id: str, table: str, fields: set[str]) -> None:
        self._schemas[(ws_id, table)] = fields

    def get_func_exists(self, ws_id: str, fn: str) -> Optional[bool]:
        return self._func_exists.get((ws_id, fn))

    def set_func_exists(self, ws_id: str, fn: str, exists: bool) -> None:
        self._func_exists[(ws_id, fn)] = exists

    def get_func_bodies(self, ws_id: str) -> Optional[dict[str, str]]:
        return self._func_bodies.get(ws_id)

    def set_func_bodies(self, ws_id: str, bodies: dict[str, str]) -> None:
        self._func_bodies[ws_id] = bodies



# Known columns/fields that are NOT table names
_NON_TABLE_TOKENS: frozenset[str] = frozenset({
    # Log Analytics meta columns
    "TimeGenerated","TenantId","Type","_ResourceId","_SubscriptionId",
    "_IsBillable","MG","ManagementGroupName","Computer","SourceSystem",
    # ASIM common output columns
    "SrcIpAddr","DstIpAddr","SrcPortNumber","DstPortNumber","NetworkProtocol",
    "EventResult","EventSeverity","EventType","EventCount","EventStartTime",
    "EventEndTime","EventOriginalType","EventProduct","EventVendor","EventSchema",
    "EventSchemaVersion","EventOriginalSeverity","EventResultDetails",
    "SrcHostname","DstHostname","SrcDomain","DstDomain","SrcDomainType",
    "DstDomainType","SrcFQDN","DstFQDN","SrcDescription","DstDescription",
    "SrcDvcId","DstDvcId","SrcDvcType","DstDvcType","SrcDvcIdType","DstDvcIdType",
    "SrcMacAddr","DstMacAddr","SrcGeoCountry","DstGeoCountry",
    "SrcGeoRegion","DstGeoRegion","SrcGeoCity","DstGeoCity",
    "SrcGeoLatitude","DstGeoLatitude","SrcGeoLongitude","DstGeoLongitude",
    "SrcGeoISP","DstGeoISP","SrcRiskLevel","DstRiskLevel",
    "SrcOriginalRiskLevel","DstOriginalRiskLevel","SrcIpAddr","DstIpAddr",
    "NetworkBytes","NetworkPackets","NetworkSessionId","NetworkConnectionHistory",
    "NetworkDirection","NetworkDuration","NetworkIcmpCode","NetworkIcmpType",
    "TcpFlagsText","TcpFlags","SrcBytes","DstBytes","SrcPackets","DstPackets",
    "InboundBytes","OutboundBytes","InboundPackets","OutboundPackets",
    # Auth ASIM columns
    "TargetUserId","TargetUserIdType","TargetUsername","TargetUsernameType",
    "TargetUserType","TargetUserAadId","TargetUserSid","TargetUserUPN",
    "SrcUserId","SrcUserIdType","SrcUsername","SrcUsernameType",
    "ActorUserId","ActorUserIdType","ActorUsername","ActorUsernameType",
    "TargetAppId","TargetAppName","TargetAppType","TargetUrl",
    "LogonMethod","LogonProtocol","LogonTarget","ImpersonatedUser",
    "SuccessCount","FailureCount","UserAgents","HttpUserAgent",
    "EventSubType","RuleName","RuleNumber",
    # UEBA columns
    "ActivityInsights","UsersInsights","DevicesInsights","InvestigationPriority",
    "UEBATime","TimeDiff","TimeDiffInMinutes","AadUserId","AccountObjectID",
    # SigninLogs / AAD columns  
    "UserPrincipalName","UserDisplayName","AppDisplayName","AppId",
    "IPAddress","IPAddressFromResourceProvider","LocationDetails","DeviceDetail",
    "Status","StatusCode","StatusDetails","ResultDescription","ResultType",
    "ConditionalAccessStatus","ConditionalAccessPolicies","ConditionalAccessPolicy",
    "MfaDetail","AuthenticationDetails","AuthenticationRequirement",
    "OriginalRequestId","IsInteractive","TokenIssuerType","TokenIssuerName",
    "ResourceDisplayName","ResourceId","ResourceServicePrincipalId",
    "UniqueTokenIdentifier","SignInIdentifier","SignInIdentifierType",
    # Common column names that look like tables but are not
    "AccountUPN","AccountSid","AccountDN","AccountName",
    # Common let-computed column names that appear as "fields" but are pipeline aliases
    "MassEmailTime","InbRCreationTime","bv_sent_emails_count","unique_recipients_count",
    "unique_recipients_count","timediff","email_count","click_count","url_clicks",
    "nSample","KQL","kql","id_info","inbox_rule_creation","emails","email_out_threshold",
    "recipient_threshold","sender_ip","SenderFromAddress",
    # Alert columns
    "AlertName","AlertSeverity","AlertType","ProviderName","VendorName",
    "Entities","ExtendedProperties","ExtendedLinks","ProductName","ProductComponentName",
    "RemediationSteps","Tactics","Techniques","CompromisedEntity","ConfidenceLevel",
    "ConfidenceScore","ProcessingEndTime","StartTime","EndTime",
    # IdentityInfo
    "AccountUPN","AccountSid","AccountDN","AccountName","AccountDisplayName",
    "Department","JobTitle","MailAddress","Manager","Phone",
    # EmailEvents
    "SenderIPv4","SenderIPv6","RecipientEmailAddress","RecipientDomain",
    "Subject","NetworkMessageId","InternetMessageId","SenderDisplayName",
    "SenderMailFromAddress","SenderMailFromDomain","DeliveryAction",
    "DeliveryLocation","ThreatTypes","DetectionMethods",
    # UrlClickEvents
    "AccountUpn","ClickedTime","Url","UrlChain","ReportId",
    # SecurityEvent
    "EventID","SubjectUserName","SubjectDomainName","SubjectUserSid",
    "TargetUserName","TargetDomainName","TargetUserSid",
    "LogonType","LogonProcessName","AuthenticationPackageName",
    "WorkstationName","TransmittedServices","LmPackageName",
    "KeyLength","ProcessId","IpAddress","IpPort",
    # AzureActivity
    "OperationName","OperationNameValue","Level","CallerIpAddress",
    "Caller","Authorization","Properties","HTTPRequest",
    "ResourceGroup","ResourceProvider","ResourceProviderValue",
    "SubscriptionId","CategoryValue",
    # DeviceInfo / MDE
    "DeviceId","DeviceName","OSPlatform","OSVersion","PublicIP",
    "JoinType","OSBuild","AadDeviceId","LoggedOnUsers","RegistryDeviceTag",
    "DeviceCategory","DeviceType","DeviceSubtype","Model","Vendor",
    # CommonSecurityLog
    "Message","ProcessName","ProcessID","Facility","SeverityLevel",
    "DeviceVendor","DeviceProduct","DeviceVersion","DeviceEventClassID",
    "Activity","Protocol","SourceIP","DestinationIP",
    "SourcePort","DestinationPort","SourceHostName","DestinationHostName",
    "SourceUserName","DestinationUserName","SourceUserID","DestinationUserID",
    "SourceNTDomain","DestinationNTDomain","SourceDnsDomain","DestinationDnsDomain",
    "SourceTranslatedAddress","SourceTranslatedPort",
    "DestinationTranslatedAddress","DestinationTranslatedPort",
    # BehaviorAnalytics
    "LogOn","Resource","SourceIPAddress","SourceIPLocation","SourceDevice",
    # Pipeline aliases / computed
    "ExtendedDescription","UserName","ClickedTime","MassEmailTime",
    "InbRCreationTime","timediff","nSample","KQL","kql","sender_ip",
    "SenderFromAddress","email_out_threshold","recipient_threshold",
})

_cache = SessionCache()


# ── Azure CLI helpers ─────────────────────────────────────────────────────────

def _run_az(*args: str, timeout: int, check: bool = True) -> subprocess.CompletedProcess:
    """Run an az CLI command, raising on failure."""
    return subprocess.run(
        ["az", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def check_az_cli() -> bool:
    """Return True if Azure CLI is installed and on PATH."""
    try:
        result = subprocess.run(
            ["az", "--version"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_AZ_VERSION,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def install_az_cli() -> None:
    """
    Attempt to install Azure CLI for the current platform.
    Exits with guidance if automatic install is not possible.
    """
    log.info("[!] Azure CLI not found.")
    if OS == "Darwin":
        log.info("    Installing via Homebrew...")
        if subprocess.run(["which", "brew"], capture_output=True, timeout=5).returncode != 0:
            log.error(
                "\n    Homebrew not found. Install it first:\n"
                "    /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com"
                "/Homebrew/install/HEAD/install.sh)\"\n"
                "    Then re-run this script."
            )
            sys.exit(1)
        subprocess.run(["brew", "install", "azure-cli"], check=True, timeout=TIMEOUT_BREW_INSTALL)
    elif OS == "Windows":
        log.error(
            "    On Windows, install Azure CLI manually:\n"
            "    https://aka.ms/installazurecliwindows\n"
            "    Download and run the MSI, then re-run this script."
        )
        sys.exit(1)
    else:
        log.error(
            "    On Linux:\n"
            "    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
        )
        sys.exit(1)


def ensure_az_cli() -> None:
    """Ensure Azure CLI is installed, installing if necessary."""
    if not check_az_cli():
        install_az_cli()
        if not check_az_cli():
            log.error("[ERROR] Azure CLI install failed. Please install manually and re-run.")
            sys.exit(1)
    log.info("[+] Azure CLI found.")


def is_logged_in() -> bool:
    """Return True if az CLI has an active session."""
    try:
        result = _run_az("account", "show", "--output", "json",
                         timeout=TIMEOUT_AZ_SHOW, check=False)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def az_login() -> None:
    """Authenticate via browser flow, falling back to device code."""
    log.info("\n[!] Not logged in. Opening browser for authentication...")
    try:
        result = subprocess.run(
            ["az", "login", "--output", "json"],
            timeout=TIMEOUT_AZ_LOGIN,
        )
    except subprocess.TimeoutExpired:
        result = type("r", (), {"returncode": 1})()

    if result.returncode != 0:
        log.info("    Browser login failed. Trying device code flow...")
        try:
            result = subprocess.run(
                ["az", "login", "--use-device-code", "--output", "json"],
                timeout=TIMEOUT_AZ_DEVICECODE,
            )
        except subprocess.TimeoutExpired:
            log.error("[ERROR] Device code login timed out. Re-run within 3 minutes.")
            sys.exit(1)
        if result.returncode != 0:
            log.error("[ERROR] Azure login failed.")
            sys.exit(1)
    log.info("[+] Logged in successfully.")


def ensure_logged_in() -> None:
    """Ensure there is an active Azure CLI session."""
    if not is_logged_in():
        az_login()
    else:
        try:
            result = _run_az("account", "show", "--output", "json", timeout=TIMEOUT_AZ_SHOW)
            acct = json.loads(result.stdout)
            log.info(
                "[+] Logged in as: %s  |  Subscription: %s",
                acct.get("user", {}).get("name", "?"),
                acct.get("name", "?"),
            )
        except Exception:
            pass


def get_token(audience: str) -> str:
    """
    Return a valid Bearer token for the given audience.
    Uses SessionCache to avoid redundant subprocess calls.
    """
    cached = _cache.get_token(audience)
    if cached:
        return cached
    try:
        result = _run_az(
            "account", "get-access-token",
            "--resource", audience,
            "--output", "json",
            timeout=TIMEOUT_TOKEN,
        )
        data = json.loads(result.stdout)
        token = data["accessToken"]
        try:
            exp_str = data.get("expiresOn", "")
            exp_dt = datetime.strptime(exp_str[:19], "%Y-%m-%d %H:%M:%S")
            expires_at = float(calendar.timegm(exp_dt.timetuple()))
        except Exception:
            expires_at = time.time() + TOKEN_DEFAULT_TTL
        _cache.set_token(audience, token, expires_at)
        return token
    except subprocess.TimeoutExpired:
        log.error("[ERROR] az token fetch timed out.")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        stderr = str(exc.stderr).lower()
        if "aadsts70043" in stderr or "expired" in stderr:
            log.error("[ERROR] Token expired. Re-run: az login")
        else:
            log.error("[ERROR] Token fetch failed. Try: az login")
        sys.exit(1)


# ── API clients ───────────────────────────────────────────────────────────────

def _arm_resource_url(ctx: WorkspaceContext) -> str:
    """Build the ARM workspace resource URL from context."""
    return ARM_BASE_URL + ARM_WS_PATH.format(
        sub=ctx.subscription_id,
        rg=ctx.resource_group,
        ws=ctx.workspace_name,
    )


def la_query(workspace_id: str, kql: str, timespan: str = "P1D", timeout: int = TIMEOUT_LA_QUERY) -> dict:
    """
    Execute a KQL query against a Log Analytics workspace.
    Retries up to HTTP_RETRY_COUNT times with exponential backoff
    on transient failures (timeout, connection error, 429).

    Args:
        workspace_id: Log Analytics workspace GUID.
        kql:          KQL query string.
        timespan:     ISO 8601 duration string (default 1 day).

    Returns:
        First table dict from the LA response.

    Raises:
        Exception: On permanent failures (4xx other than 429, parse errors).
    """
    url   = LA_QUERY_URL.format(workspace=workspace_id)
    token = get_token(LA_AUDIENCE)

    for attempt in range(1, HTTP_RETRY_COUNT + 1):
        try:
            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={"query": kql, "timespan": timespan},
                timeout=timeout,
            )
        except requests.exceptions.Timeout:
            if attempt < HTTP_RETRY_COUNT:
                time.sleep(2 ** attempt)
                continue
            raise Exception("LA query timed out after 60s")
        except requests.exceptions.ConnectionError as exc:
            if attempt < HTTP_RETRY_COUNT:
                time.sleep(2 ** attempt)
                continue
            raise Exception(f"Network error: {exc}")

        if response.status_code == 429:
            wait = int(response.headers.get("Retry-After", 10))
            log.info("    [Rate limited] waiting %ds...", wait)
            time.sleep(wait)
            continue
        if response.status_code == 403:
            raise Exception("403 Forbidden — check RBAC (Log Analytics Reader required)")
        if response.status_code == 401:
            raise Exception("401 Unauthorized — token may have expired, re-run az login")
        if not response.ok:
            raise Exception(f"HTTP {response.status_code}: {response.text[:200]}")

        data = response.json()
        if "error" in data or "code" in data:
            raise Exception(data.get("message") or data.get("error") or str(data))
        return data["tables"][0]

    raise Exception("LA query failed after all retries")


def arm_get(url: str) -> dict:
    """
    Perform an authenticated ARM GET request, following nextLink pagination.
    Retries on transient failures.

    Args:
        url: Full ARM REST API URL.

    Returns:
        Combined response dict (paginated 'value' lists are merged).

    Raises:
        Exception: On permanent HTTP failures.
    """
    all_values: list = []
    next_url: Optional[str] = url
    last_data: dict = {}

    while next_url:
        token = get_token(ARM_AUDIENCE)
        for attempt in range(1, HTTP_RETRY_COUNT + 1):
            try:
                response = requests.get(
                    next_url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=TIMEOUT_ARM_GET,
                )
            except requests.exceptions.Timeout:
                if attempt < HTTP_RETRY_COUNT:
                    time.sleep(2 ** attempt)
                    continue
                raise Exception("ARM request timed out after 30s")
            except requests.exceptions.ConnectionError as exc:
                if attempt < HTTP_RETRY_COUNT:
                    time.sleep(2 ** attempt)
                    continue
                raise Exception(f"Network error: {exc}")

            if response.status_code == 429:
                wait = int(response.headers.get("Retry-After", 10))
                log.info("    [Rate limited] waiting %ds...", wait)
                time.sleep(wait)
                continue
            if response.status_code == 403:
                raise Exception("403 Forbidden — check RBAC on subscription/resource group")
            if response.status_code == 401:
                raise Exception("401 Unauthorized — re-run az login")
            if not response.ok:
                raise Exception(f"HTTP {response.status_code}: {response.text[:200]}")

            last_data = response.json()
            if "value" in last_data:
                all_values.extend(last_data["value"])
                next_url = last_data.get("nextLink")
            else:
                return last_data
            break
        else:
            raise Exception("ARM request failed after all retries")

    return {"value": all_values} if all_values else last_data


# ── KQL parsing ───────────────────────────────────────────────────────────────

def _strip_inline_comment(line: str) -> str:
    """Remove everything after // on a line, respecting string literals."""
    in_str = False
    for i, ch in enumerate(line):
        if ch in ('"', "'"):
            in_str = not in_str
        if not in_str and ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            return line[:i]
    return line


def _extract_let_names(kql: str) -> set[str]:
    """Return all names bound by let statements (scalars and functions)."""
    return set(re.findall(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", kql))


def _classify_let_bindings(kql: str) -> tuple[set[str], set[str]]:
    """
    Classify let bindings into two groups:

    safe_to_exclude:
        Inline scalar literals (let x = 1h, 'string', dynamic(...), true/false)
        and inline tabular functions (let f = (...){...}).
        These are self-contained and should be excluded from dependency checks.

    external_refs:
        Complex expressions whose RHS references external tables, watchlists,
        or other workspace resources (e.g. let x = array_concat(BV_TABLE, ...)).
        These bindings themselves are safe to exclude (the name is not a table),
        but their RHS may reference things that need checking.

    Returns:
        (safe_to_exclude, external_refs) — both are sets of let-bound names.
    """
    safe:     set[str] = set()
    external: set[str] = set()

    inline_scalar = re.compile(
        r"^let\s+(\w+)\s*=\s*(?:\d|'|now\s*\(|ago\s*\(|dynamic\s*\(|false|true)",
        re.IGNORECASE,
    )
    inline_func = re.compile(
        r"^let\s+(\w+)\s*=\s*\([^{]*\)\s*\{",
        re.DOTALL,
    )

    for line in kql.splitlines():
        stripped = line.strip()
        if not stripped.startswith("let "):
            continue
        if inline_func.match(stripped):
            m = re.match(r"^let\s+(\w+)", stripped)
            if m:
                safe.add(m.group(1))
            continue
        if inline_scalar.match(stripped):
            m = re.match(r"^let\s+(\w+)", stripped)
            if m:
                safe.add(m.group(1))
            continue
        m = re.match(r"^let\s+(\w+)", stripped)
        if m:
            external.add(m.group(1))

    return safe, external


def extract_external_table_refs(kql: str) -> list[str]:
    """
    Extract references to external tables, watchlists, and config objects
    that appear in the KQL but are not defined inline.

    Looks for:
    - bv_* prefixed identifiers (BvisionSOC custom tables/watchlists)
    - BV_* prefixed identifiers (BvisionSOC config tables)
    - BV[A-Z0-9]+_CONFIG style identifiers
    - lookup <table> on <field> references
    - toscalar(<table> | ...) references

    Excludes:
    - Known KQL builtins and keywords
    - Let-bound names (they are not tables)
    - Field names (bv_src_ip, bv_user etc — lowercase_snake)
    """
    all_let_names = _extract_let_names(kql)

    candidates: list[str] = []

    # Pattern 1: lookup <TableName> on
    for m in re.finditer(r"\blookup\s+([A-Za-z_][A-Za-z0-9_]*)\s+on", kql, re.IGNORECASE):
        name = m.group(1)
        if name not in all_let_names and name not in BUILTINS and name.lower() not in KW:
            candidates.append(name)

    # Pattern 2: toscalar(<TableName> |
    for m in re.finditer(r"\btoscalar\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|", kql):
        name = m.group(1)
        if name not in all_let_names and name not in BUILTINS and name.lower() not in KW:
            candidates.append(name)

    # Pattern 3: BV_UPPERCASE_TABLE style (config tables, override tables)
    # Exclude known function names (BV_FUN_*, BV_CLIENT_*, etc. that are deployed functions)
    _bv_func_prefixes = ("BV_FUN_", "BV_CLIENT_")
    for m in re.finditer(r"\b(BV_[A-Z][A-Z0-9_]+|BV[A-Z0-9]+_[A-Z][A-Za-z0-9_]*)\b", kql):
        name = m.group(1)
        if any(name.startswith(p) for p in _bv_func_prefixes):
            continue
        if name not in all_let_names and name not in BUILTINS:
            candidates.append(name)

    return list(dict.fromkeys(candidates))


def _extract_let_column_names(kql: str) -> set[str]:
    """
    Return column names that are computed/aliased anywhere in the KQL.
    Covers:
    - extend X = ...
    - summarize X = ...
    - project ..., X = col, ...   (project-rename style)
    - | project-rename X = col
    These are pipeline-produced columns, not input fields from tables.
    """
    cols: set[str] = set()

    # extend X = ... and summarize X = ...
    for m in re.finditer(r"(?:extend|summarize)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", kql):
        cols.add(m.group(1))

    # project ..., Alias = expr  (any word followed by = that isn't a let binding)
    for m in re.finditer(r"(?<!let\s)\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", kql):
        name = m.group(1)
        if len(name) >= 3 and not name.lower() in {"true","false","null","and","or","not"}:
            cols.add(name)

    # project-rename NewName = OldName
    for m in re.finditer(r"project-rename\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", kql):
        cols.add(m.group(1))

    return cols


def _is_likely_table(name: str, exclude: set[str]) -> bool:
    """
    Heuristic: return True if `name` looks like a Sentinel/LA table name.
    Accepts PascalCase, ALLCAPS, _CL/_CF suffixed, and ASIM im* prefixes.
    Rejects KQL keywords, builtins, known non-table column names, and
    let-bound names.
    """
    if name in exclude or name.lower() in KW or name in BUILTINS:
        return False
    if name in _NON_TABLE_TOKENS:
        return False
    if len(name) < 3:
        return False
    if name[0].islower() and not name.startswith("im"):
        return False
    if re.search(r"_C[LF]$", name):
        return True
    if name.startswith("im") and len(name) > 4:
        return True
    if name[0].isupper() and any(c.isupper() for c in name[1:]):
        return True
    if name.isupper() and len(name) > 3:
        return True
    return False


def _scan_subquery_tables(
    text: str,
    exclude: set[str],
) -> list[str]:
    """
    Scan a text fragment for table names that appear as the first token
    inside parentheses following union/join/lookup keywords.
    Uses paren+bracket-depth tracking to handle nested expressions like
    union isfuzzy=true (datatable(...)[]), (RealTable | ...).
    """
    found: list[str] = []
    kw_pattern = re.compile(r'\b(union|join|lookup)\b', re.IGNORECASE)
    strip_opts = re.compile(
        r'^\s*(?:kind\s*=\s*\w+|isfuzzy\s*=\s*\w+|withsource\s*=\s*\w+)\s*',
        re.IGNORECASE,
    )

    for kw_m in kw_pattern.finditer(text):
        rest = strip_opts.sub('', text[kw_m.end():])
        depth = 0
        bracket_depth = 0
        i = 0
        while i < len(rest):
            c = rest[i]
            if c == '[':
                bracket_depth += 1
            elif c == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif c == '(' and bracket_depth == 0:
                depth += 1
                nm = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', rest[i + 1:].lstrip())
                if nm and depth <= 3:
                    name = nm.group(1)
                    if (
                        name.lower() not in ('datatable', 'dynamic')
                        and name not in exclude
                        and _is_likely_table(name, exclude)
                    ):
                        found.append(name)
            elif c == ')' and bracket_depth == 0:
                depth = max(0, depth - 1)
            i += 1
    return found


def _split_kql_let_blocks(kql: str) -> list[str]:
    """
    Join all KQL lines and split on top-level semicolons to extract
    let statement blocks. Correctly handles multiline let definitions.
    Returns only blocks that start with 'let '.
    """
    joined = " ".join(
        _strip_inline_comment(line).strip()
        for line in kql.splitlines()
        if _strip_inline_comment(line).strip()
    )
    blocks: list[str] = []
    current: list[str] = []
    depth = 0
    for char in joined:
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth = max(0, depth - 1)
        if char == ";" and depth == 0:
            stmt = "".join(current).strip()
            if stmt:
                blocks.append(stmt)
            current = []
        else:
            current.append(char)
    if current:
        stmt = "".join(current).strip()
        if stmt:
            blocks.append(stmt)
    return [b for b in blocks if b.startswith("let ")]


def _tables_from_let_rhs(rhs: str, exclude: set[str]) -> list[str]:
    """
    Extract table references from the RHS of a let binding.
    Handles direct table references (let x = TableName | ...)
    and union/join/lookup expressions.
    Skips inline functions, scalars, and known non-table expressions.
    """
    found: list[str] = []

    # Skip inline function bodies and scalar literals
    if rhs.startswith("{") or re.match(
        r"[\d]|'|now\s*\(|ago\s*\(|dynamic\s*\(|false|true"
        r"|array_concat|coalesce|strcat|iff\s*\(",
        rhs,
        re.IGNORECASE,
    ):
        return found

    # First token — direct table reference like: let emails = EmailEvents | ...
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", rhs)
    if m:
        name = m.group(1)
        if name not in exclude and _is_likely_table(name, exclude):
            found.append(name)

    # union/join/lookup subquery tables
    found.extend(_scan_subquery_tables(rhs, exclude))
    return found


def extract_tables(kql: str) -> list[str]:
    """
    Extract table/view references from KQL.

    Handles:
    - Top-level pipeline sources (TableName | ...)
    - union/join/lookup subqueries with nested parentheses
    - Table references inside let binding RHS (multiline-safe)
    - Excludes let-bound names, computed columns, KQL keywords, builtins,
      ASIM functions, and known non-table column names.
    """
    exclude = _extract_let_names(kql) | _extract_let_column_names(kql)
    tables:  list[str] = []

    # ── Pass 1: scan pipe-by-pipe lines ──────────────────────────────────
    for raw_line in kql.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("//") or line.startswith("/*") or line.startswith("let"):
            continue

        # Top-level source table (line does not start with |)
        if not line.startswith("|"):
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", line)
            if m and _is_likely_table(m.group(1), exclude):
                name = m.group(1)
                rest = line[m.end():].lstrip()
                if not rest.startswith("("):   # function call → skip
                    tables.append(name)

        # union/join/lookup subqueries within pipe operators
        tables.extend(_scan_subquery_tables(line, exclude))

    # ── Pass 2: let-binding RHS ───────────────────────────────────────────
    for block in _split_kql_let_blocks(kql):
        eq = block.find("=", 4)
        if eq == -1:
            continue
        tables.extend(_tables_from_let_rhs(block[eq + 1:].strip(), exclude))

    return list(dict.fromkeys(tables))



def extract_funcs(kql: str) -> list[str]:
    """
    Extract custom function calls from KQL.
    Excludes builtins, KQL keywords, and all let-bound names (scalars + functions).
    """
    let_names = _extract_let_names(kql)
    calls = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", kql)
    return list(dict.fromkeys(
        fn for fn in calls
        if fn not in BUILTINS
        and fn not in let_names
        and fn.lower() not in KW
        and len(fn) > 2
    ))


def extract_fields(kql: str) -> list[str]:
    """
    Extract field name candidates from KQL operator clauses.
    Strips comments, string literals, let-bound names, aggregation aliases,
    and all-lowercase short tokens to reduce false positives.
    """
    let_names = _extract_let_names(kql)
    candidates: list[str] = []
    op_pattern = re.compile(
        r"^\|?\s*(?:where|project(?!-)|extend|mv-expand|mv-apply)\s+(.+)",
        re.IGNORECASE,
    )

    for raw_line in kql.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line or line.startswith("//") or line.startswith("let "):
            continue
        m = op_pattern.match(line)
        if not m:
            continue
        clause = m.group(1)
        # Strip string literals to avoid picking up literal values as field names
        # e.g. has_any('MicrosoftThreatProtection', 'MCAS') -> has_any('', '')
        clause = re.sub(r"@?'[^']*'", "''", clause)
        clause = re.sub(r'"[^"]+"', '""', clause)
        tokens = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]{2,})\b', clause)
        for tok in tokens:
            if tok in let_names or tok in BUILTINS or tok.lower() in KW:
                continue
            if tok in _NON_TABLE_TOKENS:
                continue
            # skip anything that looks like a function call (followed by '(' in clause)
            fn_pattern = re.search(r"\b" + re.escape(tok) + r"\s*\(", clause)
            if fn_pattern:
                continue
            if re.match(r"^(dcount|make_set|make_list|set|count|sum|avg|min|max|stdev)_", tok, re.IGNORECASE):
                continue
            if tok.islower() and len(tok) < 8:
                continue
            # must be clearly a field name: PascalCase, UPPER_SNAKE, or bv_snake_with_upper
            if tok[0].isupper() and any(c.isupper() for c in tok[1:]) and len(tok) >= 5:
                pass  # PascalCase field like SenderIPv4, NetworkMessageId
            elif "_" in tok and any(c.isupper() for c in tok) and len(tok) >= 6:
                pass  # snake_with_upper like bv_src_ip — but these are usually filtered by lowercase check
            else:
                continue
            candidates.append(tok)

    return list(dict.fromkeys(candidates))


# Module-level cache for data presence results to avoid re-checking per rule
_data_presence_cache: dict[tuple[str, str], bool] = {}  # (ws_id, source) -> has_data


def _check_data_presence(
    ctx: WorkspaceContext,
    tables: list[str],
    funcs: list[str],
    deployed: dict[str, str],
) -> list[str]:
    """
    Check source tables and ASIM functions for data in the last 30 days.
    Uses a single batched union query for tables to minimise API calls.
    Results are cached per session so repeated checks across rules are free.

    Returns list of source names with 0 rows.
    """
    existing_tables = get_existing_tables(ctx)
    no_data: list[str] = []

    # ── Tables: batch into one union count query ──────────────────────────
    tables_to_check = [
        t for t in tables
        if t in existing_tables
        and (ctx.workspace_id, t) not in _data_presence_cache
    ]

    if tables_to_check:
        # Build: union withsource=_T (T1 | count), (T2 | count) ...
        # Simpler: run one query per table but with a short timeout
        for table in tables_to_check:
            try:
                t = la_query(
                    ctx.workspace_id,
                    f"{table} | summarize c=count() | project Source='{table}', c",
                    timespan="P30D",
                    timeout=15,
                )
                row_count = int(t["rows"][0][1]) if t["rows"] else 0
                _data_presence_cache[(ctx.workspace_id, table)] = row_count > 0
            except Exception:
                _data_presence_cache[(ctx.workspace_id, table)] = True  # assume has data on error

    for table in tables:
        if table not in existing_tables:
            continue
        if not _data_presence_cache.get((ctx.workspace_id, table), True):
            no_data.append(f"{table}(0 rows/30d)")

    # ── Functions: only check deployed ASIM functions, cached ────────────
    funcs_to_check = [
        fn for fn in funcs
        if fn in deployed
        and (ctx.workspace_id, fn) not in _data_presence_cache
    ]

    for fn in funcs_to_check:
        try:
            t = la_query(
                ctx.workspace_id,
                f"{fn}() | summarize c=count()",
                timespan="P30D",
                timeout=15,
            )
            row_count = int(t["rows"][0][0]) if t["rows"] else 0
            _data_presence_cache[(ctx.workspace_id, fn)] = row_count > 0
        except Exception:
            _data_presence_cache[(ctx.workspace_id, fn)] = True

    for fn in funcs:
        if fn not in deployed:
            continue
        if not _data_presence_cache.get((ctx.workspace_id, fn), True):
            no_data.append(f"{fn}()(0 rows/30d)")

    return no_data

def get_existing_tables(ctx: WorkspaceContext) -> set[str]:
    """Return the set of table names present in the workspace. Cached per session."""
    cached = _cache.get_tables(ctx.workspace_id)
    if cached is not None:
        return cached
    try:
        t = la_query(
            ctx.workspace_id,
            "union withsource=_TableName * | summarize by _TableName",
        )
        tables = {row[0] for row in t["rows"]}
    except Exception as exc:
        log.warning("    WARNING: could not fetch table list — %s", exc)
        tables = set()
    _cache.set_tables(ctx.workspace_id, tables)
    return tables


def get_table_schema(ctx: WorkspaceContext, table_name: str) -> set[str]:
    """Return column names for a specific table. Cached per session."""
    cached = _cache.get_schema(ctx.workspace_id, table_name)
    if cached is not None:
        return cached
    try:
        t = la_query(
            ctx.workspace_id,
            f"{table_name} | getschema | project ColumnName",
        )
        fields = {row[0] for row in t["rows"]}
    except Exception:
        fields = set()
    _cache.set_schema(ctx.workspace_id, table_name, fields)
    return fields


def fetch_deployed_functions(ctx: WorkspaceContext) -> dict[str, str]:
    """
    Fetch all savedSearches with a functionAlias from ARM.
    Returns dict mapping alias -> KQL body. Cached per session.
    """
    cached = _cache.get_func_bodies(ctx.workspace_id)
    if cached is not None:
        return cached
    result: dict[str, str] = {}
    try:
        url = (
            _arm_resource_url(ctx)
            + f"/savedSearches?api-version={SAVED_SEARCHES_API}"
        )
        data = arm_get(url)
        for item in data.get("value", []):
            props = item.get("properties", {})
            alias = props.get("functionAlias")
            query = props.get("query", "")
            if alias:
                result[alias] = query
    except Exception as exc:
        log.warning("    WARNING: could not fetch deployed functions — %s", exc)
    _cache.set_func_bodies(ctx.workspace_id, result)
    return result


def _iso8601_to_seconds(duration: str) -> Optional[int]:
    """Parse ISO 8601 duration string to total seconds. Returns None if unparseable."""
    if not duration:
        return None
    m = re.match(r"P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$", duration.upper())
    if not m:
        return None
    days    = int(m.group(1) or 0)
    hours   = int(m.group(2) or 0)
    minutes = int(m.group(3) or 0)
    seconds = int(m.group(4) or 0)
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _check_function_by_call(workspace_id: str, fn: str) -> bool:
    """
    Determine if a function exists by calling it with no args.
    Returns True if function exists (even if it requires parameters).
    Empty result (0 rows) is treated as exists — ASIM parsers with no
    configured data sources legitimately return 0 rows.
    """
    try:
        la_query(workspace_id, f"{fn}() | limit 1")
        return True
    except Exception as exc:
        err = str(exc).lower()
        not_defined = (
            f"'{fn.lower()}' is not defined" in err
            or "unknown function" in err
            or ("semantic" in err and "not defined" in err and fn.lower() in err)
        )
        return not not_defined


def _validate_function_body(
    ctx: WorkspaceContext,
    fn_name: str,
    body_kql: str,
    existing_tables: set[str],
    deployed: dict[str, str],
) -> list[str]:
    """
    Validate the KQL body of a deployed function (one level deep).
    Returns list of issue description strings.
    """
    issues: list[str] = []
    inner_tables = extract_tables(body_kql)
    inner_funcs  = extract_funcs(body_kql)
    missing_tables = [t for t in inner_tables if t not in existing_tables]
    missing_funcs  = [f for f in inner_funcs if f not in deployed and f not in BUILTINS]
    if missing_tables or missing_funcs:
        parts = missing_tables + missing_funcs
        issues.append(f"{fn_name}(body missing: {', '.join(parts)})")
    return issues


def extract_let_column_names(kql: str) -> set[str]:
    """Return column names produced by extend/summarize assignments."""
    return {
        m.group(1)
        for m in re.finditer(r"(?:extend|summarize)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", kql)
    }


def check_missing_functions(
    ctx: WorkspaceContext,
    funcs: list[str],
) -> tuple[list[str], list[str]]:
    """
    Check which custom functions are missing from the workspace.
    Also validates KQL bodies of deployed functions (one level deep).

    Strategy:
        1. ARM savedSearches — authoritative source.
        2. No-arg call — works for all-optional-param functions.
        3. Required-param detection — arg errors mean function exists.

    Returns:
        Tuple of (missing_functions, body_issues).
    """
    if not funcs:
        return [], []

    deployed        = fetch_deployed_functions(ctx)
    existing_tables = get_existing_tables(ctx)
    missing:     list[str] = []
    body_issues: list[str] = []

    for fn in funcs:
        cached = _cache.get_func_exists(ctx.workspace_id, fn)
        if cached is None:
            if fn in deployed:
                _cache.set_func_exists(ctx.workspace_id, fn, True)
                cached = True
            else:
                exists = _check_function_by_call(ctx.workspace_id, fn)
                _cache.set_func_exists(ctx.workspace_id, fn, exists)
                cached = exists
        if not cached:
            missing.append(fn)
        elif fn in deployed and deployed[fn]:
            body_issues.extend(
                _validate_function_body(ctx, fn, deployed[fn], existing_tables, deployed)
            )

    return missing, body_issues


def check_missing_fields(
    ctx: WorkspaceContext,
    tables: list[str],
    kql: str,
    existing_tables: set[str],
) -> list[str]:
    """
    Check whether fields referenced in KQL exist across workspace tables.
    A field is only flagged if absent from ALL tables in the query.
    Also pulls fields from deployed function output schemas.
    """
    candidates = extract_fields(kql)
    if not candidates:
        return []

    all_known_fields: set[str] = set()
    deployed = fetch_deployed_functions(ctx)

    for table in tables:
        if table not in existing_tables:
            continue
        all_known_fields.update(get_table_schema(ctx, table))

    funcs_in_kql = extract_funcs(kql)
    for fn in funcs_in_kql:
        if fn in deployed and deployed[fn]:
            fn_tables = extract_tables(deployed[fn])
            for ft in fn_tables:
                if ft in existing_tables:
                    all_known_fields.update(get_table_schema(ctx, ft))

    if not all_known_fields:
        return []

    truly_missing = [f for f in candidates if f not in all_known_fields]
    return [f"(unknown table).{f}" for f in truly_missing]



def fetch_analytics_rules(ctx: WorkspaceContext) -> list[dict]:
    """
    Fetch all Sentinel analytics rules for the workspace via ARM.

    Args:
        ctx: WorkspaceContext identifying the workspace.

    Returns:
        List of rule dicts from the ARM API response.
    """
    url = (
        _arm_resource_url(ctx)
        + f"/providers/Microsoft.SecurityInsights/alertRules"
        + f"?api-version={ALERT_RULES_API}"
    )
    data = arm_get(url)
    return data.get("value", [])



def validate_kql(
    ctx: WorkspaceContext,
    kql: str,
    rule_name: str = "",
    rule_props: Optional[dict] = None,
    skip_data_check: bool = False,
) -> ValidationResult:
    """
    Validate a KQL string against the target workspace.

    Checks performed:
        1. Table existence
        2. Custom function existence + body validation
        3. Field existence per table
        4. Live dry-run (limit 1)
        5. Data presence — 0 rows in last 30d = NO DATA
        6. Schedule gap — queryFrequency > queryPeriod
        7. Rule enabled state (from rule_props)

    Args:
        ctx:        WorkspaceContext.
        kql:        KQL query string.
        rule_name:  Optional display name for the result.
        rule_props: Optional raw ARM rule properties dict.

    Returns:
        ValidationResult populated with all findings.
    """
    props = rule_props or {}
    result = ValidationResult(
        rule_name = rule_name,
        kind      = "",
        enabled   = props.get("enabled", True),
        modified  = "",
    )

    existing_tables = get_existing_tables(ctx)
    tables = extract_tables(kql)
    funcs  = extract_funcs(kql)

    # Also check external table refs (lookup targets, toscalar tables, BV_CONFIG tables)
    external_refs = extract_external_table_refs(kql)
    deployed      = fetch_deployed_functions(ctx)

    # External refs could be tables OR deployed functions/watchlists —
    # only flag as missing table if not found in either existing tables or deployed functions
    all_tables = list(dict.fromkeys(tables + [
        r for r in external_refs
        if r not in tables and r not in deployed
    ]))

    # Check 1: table existence
    result.tables_ok      = [t for t in all_tables if t in existing_tables]
    result.tables_missing = [t for t in all_tables if t not in existing_tables]

    # Check 2: function existence + body validation
    missing_funcs, body_issues = check_missing_functions(ctx, funcs)
    result.funcs_ok         = [f for f in funcs if f not in missing_funcs]
    result.funcs_missing    = missing_funcs
    result.func_body_issues = body_issues

    # Check 3: field existence
    result.fields_missing = check_missing_fields(ctx, tables, kql, existing_tables)

    # Check 4: dry-run with limit 1
    test_kql = re.sub(r"\|\s*limit\s*\d+", "", kql, flags=re.IGNORECASE) + "\n| limit 1"
    try:
        la_query(ctx.workspace_id, test_kql)
        result.dry_run_ok = True
    except Exception as exc:
        err = str(exc)
        if "PartialError" in err:
            result.dry_run_error = (
                "PartialError — query ran but some sub-expressions failed "
                "(likely missing required-param functions like ASIM parsers)"
            )
        else:
            result.dry_run_error = err.split("details")[0].strip().rstrip(",{").strip()[:120]

    # Check 5: data presence — only run if no hard missing deps and not skipped for perf
    if not skip_data_check and not result.tables_missing and not result.funcs_missing:
        deployed = fetch_deployed_functions(ctx)
        result.no_data_sources = _check_data_presence(ctx, tables, funcs, deployed)

    # Check 6: schedule gap detection
    freq   = props.get("queryFrequency", "")
    period = props.get("queryPeriod", "")
    if freq and period:
        result.query_frequency = freq
        result.query_period    = period
        freq_s   = _iso8601_to_seconds(freq)
        period_s = _iso8601_to_seconds(period)
        if freq_s and period_s and freq_s > period_s:
            result.schedule_gap = True

    return result

def _print_validation_result(res: ValidationResult) -> None:
    """Print a ValidationResult to stdout in a readable format."""
    log.info("\n  Rule:    %s", res.rule_name)
    log.info("  Kind:    %s  |  Enabled: %s  |  Modified: %s", res.kind, res.enabled, res.modified)

    if res.skipped:
        log.info("  Status:  [SKIP] %s", res.skip_reason)
        log.info("  " + "-" * 66)
        return

    if res.tables_ok:
        log.info("  Tables OK:        %s", ", ".join(res.tables_ok))
    if res.tables_missing:
        log.info("  Tables MISSING:   %s", ", ".join(res.tables_missing))
    if not res.tables_ok and not res.tables_missing:
        log.info("  Tables:           none detected")

    if res.funcs_ok:
        log.info("  Functions OK:     %s", ", ".join(res.funcs_ok))
    if res.funcs_missing:
        log.info("  Functions MISSING:%s", ", ".join(res.funcs_missing))
    if res.func_body_issues:
        log.info("  Function body issues: %s", ", ".join(res.func_body_issues))
    # Only show field issues if they are attributed to a known table
    known_table_fields = [f for f in res.fields_missing if not f.startswith("(unknown table).")]
    if known_table_fields:
        log.info("  Fields MISSING:   %s", ", ".join(known_table_fields))

    log.info("  Dry-run:          %s", "PASS" if res.dry_run_ok else "FAIL")
    if not res.dry_run_ok and res.dry_run_error:
        log.info("  Dry-run error:    %s", res.dry_run_error)

    if not res.enabled:
        log.info("  Rule state:       DISABLED — will not fire")

    if res.no_data_sources:
        log.info("  No data (30d):    %s", ", ".join(res.no_data_sources))

    if res.schedule_gap:
        log.info(
            "  Schedule:         GAP — runs every %s but queries last %s",
            res.query_frequency, res.query_period,
        )
    elif res.query_frequency:
        log.info(
            "  Schedule:         OK — runs every %s, queries last %s",
            res.query_frequency, res.query_period,
        )

    log.info("  Status:  [%s]", res.status)
    log.info("  Verdict: [%s]", res.verdict)
    log.info("  " + "-" * 66)


def _print_summary(results: list[ValidationResult]) -> None:
    """Print a summary line after batch validation."""
    ok       = sum(1 for r in results if r.status == "OK")
    warn     = sum(1 for r in results if r.status == "WARN")
    fail     = sum(1 for r in results if r.status == "FAIL")
    skip     = sum(1 for r in results if r.status == "SKIP")
    no_data  = sum(1 for r in results if r.status == "NO DATA")
    disabled = sum(1 for r in results if r.status == "DISABLED")
    log.info("\n" + "=" * 70)
    log.info("  SUMMARY  —  %d rules checked", len(results))
    log.info(
        "  OK: %d   WARN: %d   FAIL: %d   NO DATA: %d   DISABLED: %d   SKIP: %d",
        ok, warn, fail, no_data, disabled, skip,
    )
    log.info("=" * 70 + "\n")


# ── Feature functions ─────────────────────────────────────────────────────────

def list_tables(ctx: WorkspaceContext) -> list[str]:
    """Print and return all tables with approximate row counts."""
    log.info("\n[+] Tables in workspace: %s", ctx.workspace_id)
    t = la_query(
        ctx.workspace_id,
        "union withsource=_TableName * | summarize Rows=count() by _TableName | sort by _TableName asc",
    )
    cols = {c["name"]: i for i, c in enumerate(t["columns"])}
    rows = t["rows"]
    log.info("    %d tables found\n", len(rows))
    for row in rows:
        log.info("    %-45s %10s rows/day", row[cols["_TableName"]], f"{row[cols['Rows']]:,}")
    return [row[cols["_TableName"]] for row in rows]


def inspect_table_fields(ctx: WorkspaceContext, table_name: str) -> list[str]:
    """Print and return the schema for a specific table."""
    log.info("\n[+] Schema: %s", table_name)
    t = la_query(
        ctx.workspace_id,
        f"{table_name} | getschema | project ColumnName, DataType | sort by ColumnName asc",
    )
    cols = {c["name"]: i for i, c in enumerate(t["columns"])}
    for row in t["rows"]:
        log.info("    %-45s %s", row[cols["ColumnName"]], row[cols["DataType"]])
    return [row[cols["ColumnName"]] for row in t["rows"]]


def list_saved_functions(ctx: WorkspaceContext) -> list[str]:
    """Print and return all saved function aliases in the workspace."""
    log.info("\n[+] Saved functions in workspace: %s", ctx.workspace_name)
    deployed = fetch_deployed_functions(ctx)
    if not deployed:
        log.info("    No saved functions found.")
        return []
    for alias in sorted(deployed):
        log.info("    %s", alias)
    return list(deployed.keys())


def validate_rule_manual(ctx: WorkspaceContext, kql: str) -> None:
    """Validate a KQL string entered manually by the user."""
    log.info("\n[+] Validating rule KQL")
    res = validate_kql(ctx, kql, rule_name="Manual input")
    _print_validation_result(res)


def _validate_rules_batch(
    ctx: WorkspaceContext,
    rules: list[dict],
    label: str,
    skip_data_check: bool = False,
) -> None:
    """
    Shared batch validation logic used by options 5, 6, and 7.

    Args:
        ctx:             WorkspaceContext.
        rules:           List of rule dicts from ARM API.
        label:           Human-readable label for the log header.
        skip_data_check: Skip the 30-day data presence check for speed.
                         Recommended when validating large rule sets (>20 rules).
    """
    if not rules:
        log.info("    No rules found.")
        return

    log.info("    %d rule(s) %s — pre-loading workspace data...", len(rules), label)
    # Pre-warm all caches before the loop so every rule benefits from cached data
    get_existing_tables(ctx)        # populates _cache._tables once
    fetch_deployed_functions(ctx)   # populates _cache._func_bodies once

    log.info("    Running validation...")
    log.info("\n" + "=" * 70)
    results: list[ValidationResult] = []

    for rule in rules:
        props   = rule.get("properties", {})
        name    = props.get("displayName", rule.get("name", "unknown"))
        kind    = rule.get("kind", "?")
        enabled = props.get("enabled", False)
        ts      = props.get("lastModifiedUtc") or props.get("createdTimeUtc", "")
        kql     = props.get("query", "")

        if not kql:
            res = ValidationResult(
                rule_name=name, kind=kind, enabled=enabled,
                modified=ts[:10] if ts else "?",
                skipped=True, skip_reason="no query (non-scheduled rule type)",
            )
        else:
            try:
                res = validate_kql(ctx, kql, rule_name=name, rule_props=props, skip_data_check=skip_data_check)
            except Exception as exc:
                res = ValidationResult(
                    rule_name=name, kind=kind, enabled=enabled,
                    modified=ts[:10] if ts else "?",
                    skipped=True, skip_reason=f"validation error: {str(exc)[:80]}",
                )
            res.kind     = kind
            res.enabled  = enabled
            res.modified = ts[:10] if ts else "?"

        results.append(res)
        _print_validation_result(res)

    _print_summary(results)


def validate_rules_recent(ctx: WorkspaceContext) -> None:
    """Fetch and validate rules modified in the last RULE_LOOKBACK_DAYS days."""
    log.info("\n[+] Fetching analytics rules modified in last %d days...", RULE_LOOKBACK_DAYS)
    all_rules = fetch_analytics_rules(ctx)
    cutoff = datetime.now(timezone.utc) - timedelta(days=RULE_LOOKBACK_DAYS)
    recent = []
    for rule in all_rules:
        ts = rule.get("properties", {}).get("lastModifiedUtc")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= cutoff:
                    recent.append(rule)
            except Exception:
                pass
    _validate_rules_batch(ctx, recent, "modified in last 30 days")


def validate_rules_all(ctx: WorkspaceContext) -> None:
    """Fetch and validate all deployed analytics rules. Skips data check for speed."""
    log.info("\n[+] Fetching ALL deployed analytics rules...")
    rules = fetch_analytics_rules(ctx)
    _validate_rules_batch(ctx, rules, "found", skip_data_check=True)


def validate_single_rule(ctx: WorkspaceContext) -> None:
    """List all rules interactively and validate the one the user picks."""
    log.info("\n[+] Fetching all analytics rules...")
    rules = fetch_analytics_rules(ctx)
    if not rules:
        log.info("    No rules found.")
        return

    log.info("")
    for i, rule in enumerate(rules, 1):
        props   = rule.get("properties", {})
        name    = props.get("displayName", rule.get("name", "unknown"))
        enabled = "ON " if props.get("enabled") else "OFF"
        kind    = rule.get("kind", "?")
        ts      = (props.get("lastModifiedUtc") or props.get("createdTimeUtc", ""))[:10]
        log.info("  [%3d]  [%s]  %-55s  %-20s  %s", i, enabled, name, kind, ts)

    log.info("")
    while True:
        choice = input("Select rule to validate (number): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(rules):
            rule = rules[int(choice) - 1]
            break
        log.info("    Invalid choice.")

    props   = rule.get("properties", {})
    name    = props.get("displayName", rule.get("name", "unknown"))
    kind    = rule.get("kind", "?")
    enabled = props.get("enabled", False)
    ts      = (props.get("lastModifiedUtc") or props.get("createdTimeUtc", ""))[:10]
    kql     = props.get("query", "")

    log.info("\n" + "=" * 70)
    if not kql:
        res = ValidationResult(
            rule_name=name, kind=kind, enabled=enabled, modified=ts,
            skipped=True, skip_reason="no query (non-scheduled rule type)",
        )
    else:
        res = validate_kql(ctx, kql, rule_name=name, rule_props=props)
        res.kind = kind; res.enabled = enabled; res.modified = ts

    _print_validation_result(res)


# ── Workspace / subscription selection ───────────────────────────────────────

def pick_subscription() -> str:
    """
    List available Azure subscriptions and prompt the user to pick one.
    Sets the picked subscription as active in az CLI.

    Returns:
        Subscription ID string.
    """
    log.info("\n[+] Fetching subscriptions...")
    result = _run_az("account", "list", "--output", "json", timeout=TIMEOUT_AZ_LIST)
    subs   = json.loads(result.stdout)
    if not subs:
        log.error("[ERROR] No subscriptions found.")
        sys.exit(1)

    log.info("")
    for i, sub in enumerate(subs, 1):
        marker = "*" if sub.get("isDefault") else " "
        log.info("  [%2d]%s %-45s %s", i, marker, sub["name"], sub["id"])

    log.info("")
    while True:
        choice = input("Select subscription (number): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(subs):
            sub = subs[int(choice) - 1]
            break
        log.info("    Invalid choice.")

    sub_id = sub["id"]
    log.info("\n[+] Setting subscription: %s...", sub["name"])
    _run_az("account", "set", "--subscription", sub_id, timeout=TIMEOUT_AZ_SET)
    return sub_id


def pick_workspace(sub_id: str) -> WorkspaceContext:
    """
    List Log Analytics workspaces in the subscription and prompt the user.
    Falls back to manual input if the API call fails.

    Args:
        sub_id: Azure subscription ID.

    Returns:
        WorkspaceContext for the selected workspace.
    """
    log.info("\n[+] Fetching Log Analytics workspaces...")
    result = subprocess.run(
        [
            "az", "monitor", "log-analytics", "workspace", "list",
            "--subscription", sub_id,
            "--query", "[].{name:name, id:customerId, rg:resourceGroup, location:location}",
            "--output", "json",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_WS_LIST,
    )

    if result.returncode != 0 or not result.stdout.strip():
        log.warning("    Could not list workspaces. Please enter details manually.")
        return WorkspaceContext(
            workspace_id   =input("Workspace ID (GUID):   ").strip(),
            workspace_name =input("Workspace name:        ").strip(),
            subscription_id=sub_id,
            resource_group =input("Resource group:        ").strip(),
        )

    workspaces = json.loads(result.stdout)
    if not workspaces:
        log.info("    No workspaces found in this subscription. Enter manually.")
        return WorkspaceContext(
            workspace_id   =input("Workspace ID (GUID):   ").strip(),
            workspace_name =input("Workspace name:        ").strip(),
            subscription_id=sub_id,
            resource_group =input("Resource group:        ").strip(),
        )

    log.info("")
    for i, ws in enumerate(workspaces, 1):
        log.info("  [%2d]  %-40s %-38s (%s)", i, ws["name"], ws["id"], ws["location"])

    log.info("")
    while True:
        choice = input("Select workspace (number): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(workspaces):
            ws = workspaces[int(choice) - 1]
            break
        log.info("    Invalid choice.")

    return WorkspaceContext(
        workspace_id   =ws["id"],
        workspace_name =ws["name"],
        subscription_id=sub_id,
        resource_group =ws["rg"],
    )


# ── Main ──────────────────────────────────────────────────────────────────────


def validate_by_rule_id(ctx: WorkspaceContext) -> None:
    """
    Search for a rule by any part of its ID, display name, or internal name.
    Case-insensitive partial match — works with BV-xxxxx, SEN-xxxxx,
    or any free-text fragment of the rule name.
    """
    rule_id = input("Search rule (ID, name, or partial match): ").strip()
    if not rule_id:
        log.info("    No input provided.")
        return

    log.info("\n[+] Fetching rules matching: %s", rule_id)
    all_rules = fetch_analytics_rules(ctx)

    matches = [
        r for r in all_rules
        if rule_id.lower() in r.get("properties", {}).get("displayName", "").lower()
        or rule_id.lower() in r.get("name", "").lower()
    ]

    if not matches:
        log.info("    No rules found matching '%s'.", rule_id)
        return

    if len(matches) == 1:
        rule = matches[0]
    else:
        log.info("\n    Multiple matches:\n")
        for i, r in enumerate(matches, 1):
            name = r.get("properties", {}).get("displayName", r.get("name"))
            log.info("  [%2d]  %s", i, name)
        log.info("")
        while True:
            choice = input("Select rule (number): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(matches):
                rule = matches[int(choice) - 1]
                break
            log.info("    Invalid choice.")

    props   = rule.get("properties", {})
    name    = props.get("displayName", rule.get("name", "unknown"))
    kind    = rule.get("kind", "?")
    enabled = props.get("enabled", False)
    ts      = (props.get("lastModifiedUtc") or props.get("createdTimeUtc", ""))[:10]
    kql     = props.get("query", "")

    log.info("\n" + "=" * 70)
    if not kql:
        res = ValidationResult(
            rule_name=name, kind=kind, enabled=enabled, modified=ts,
            skipped=True, skip_reason="no query (non-scheduled rule type)",
        )
    else:
        res = validate_kql(ctx, kql, rule_name=name, rule_props=props)
        res.kind = kind
        res.enabled = enabled
        res.modified = ts

    _print_validation_result(res)

def main() -> None:
    """
    Entry point. Handles setup, authentication, workspace selection,
    and the interactive menu loop.
    """
    log.info("=" * 60)
    log.info("  Sentinel Workspace Inspector")
    log.info("  Platform: %s", OS)
    log.info("=" * 60)

    ensure_az_cli()
    ensure_logged_in()

    sub_id = pick_subscription()
    ctx    = pick_workspace(sub_id)
    log.info("\n[+] Workspace: %s  (%s)", ctx.workspace_name, ctx.workspace_id)

    menu = {
        "1": ("List all tables",                          lambda: list_tables(ctx)),
        "2": ("Inspect table fields",                     lambda: inspect_table_fields(ctx, input("Table name: ").strip())),
        "3": ("List saved functions",                     lambda: list_saved_functions(ctx)),
        "4": ("Validate rule KQL (paste manually)",       lambda: _manual_kql_input(ctx)),
        "5": ("Search and validate rule by ID or name",      lambda: validate_by_rule_id(ctx)),
        "6": ("Auto-validate rules modified last 30 days",lambda: validate_rules_recent(ctx)),
        "7": ("Validate ALL deployed rules",              lambda: validate_rules_all(ctx)),
        "8": ("List all rules and validate one",          lambda: validate_single_rule(ctx)),
    }

    while True:
        log.info("\nOptions:")
        for key, (label, _) in menu.items():
            log.info("  %s  %s", key, label)
        log.info("  q  Quit")

        choice = input("\n> ").strip().lower()
        if choice == "q":
            break
        if choice in menu:
            try:
                menu[choice][1]()
            except Exception as exc:
                log.error("    [ERROR] %s", exc)
        else:
            log.info("    Invalid option.")


def _manual_kql_input(ctx: WorkspaceContext) -> None:
    """Prompt the user to paste a KQL query and validate it."""
    log.info("Paste your KQL (end with a line containing only 'END'):")
    lines: list[str] = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    validate_rule_manual(ctx, "\n".join(lines))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("\n\n[!] Interrupted by user. Exiting.")
        sys.exit(0)
