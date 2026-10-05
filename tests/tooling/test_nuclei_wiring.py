"""The nuclei contract, and the argv that has to switch off its defaults.

nuclei given one target does a great deal more than probe it, and none of that
needs a flag. So the interesting assertions here are not that the argv contains
what we asked for -- they are that it contains the switches that stop what we
did not ask for, and that the contract offers no way to turn them off.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.mitre.techniques import techniques_for_action
from vuln_proof_claw.policy.risk import classify_risk
from vuln_proof_claw.tooling.contracts import NucleiParameters, validate_tool_invocation
from vuln_proof_claw.tooling.executor import (
    NUCLEI_DEFAULT_LEAKS,
    NUCLEI_WORKER_ENVIRONMENT,
    build_worker_argv,
)
from vuln_proof_claw.tooling.registry import IntegrationState, get_tool

TARGET = "https://api.example.test:443/v1"


def argv(**parameters: object) -> tuple[str, ...]:
    return build_worker_argv(validate_tool_invocation("nuclei", TARGET, dict(parameters)))


def test_the_required_switches_are_pinned_independently_of_the_table() -> None:
    # This list is written out on purpose. Asserting the argv against
    # NUCLEI_DEFAULT_LEAKS alone made the table its own oracle: deleting an
    # entry removed the switch from the argv AND from the assertion loop, so
    # dropping -system-resolvers -- which sends every target hostname to
    # Cloudflare and Google -- left the suite green. An earlier version of this
    # test claimed in a comment that removing an entry would be "a visible
    # change, not a quiet widening", which was the one mutation it could not
    # see.
    built = argv()

    assert {
        "-disable-update-check",
        "-no-stdin",
        "-no-httpx",
        "-system-resolvers",
        "-disable-redirects",
        "-silent",
        "-no-color",
        "-jsonl",
    } <= set(built)


def test_the_threat_model_table_stays_consistent_with_the_argv() -> None:
    # Complements the pinned list above: this half catches an entry ADDED to the
    # table without its switch reaching the command line, which the literal list
    # cannot see.
    built = argv()

    for switch, reason in NUCLEI_DEFAULT_LEAKS.items():
        assert switch in built, f"{switch} missing -- {reason}"


def test_out_of_band_detection_is_off_until_a_server_is_named() -> None:
    # nuclei's default OAST servers are the vendor's, so leaving out-of-band
    # detection on means the target's own request reaches a third party and that
    # third party learns which target was scanned. There is no boolean to flip:
    # the only way to enable it is to name the server, which cannot happen by
    # accident.
    assert "-no-interactsh" in argv()
    assert "-interactsh-server" not in argv()

    named = argv(interactsh_server="https://oast.internal.test")
    assert "-no-interactsh" not in named
    assert named[named.index("-interactsh-server") + 1] == "https://oast.internal.test"


@pytest.mark.parametrize(
    "value",
    ["oast.pro", "//oast.pro", "ftp://oast.internal.test", "https://", "not a url"],
)
def test_an_interactsh_server_that_is_not_an_absolute_url_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        validate_tool_invocation("nuclei", TARGET, {"interactsh_server": value})


def test_the_argv_can_never_reach_a_target_or_a_corpus_the_approval_did_not_name() -> None:
    built = argv(template_ids=["cve-2021-44228"], tags=["sqli"])

    forbidden = {
        # a second list of targets
        "-l",
        "-list",
        # a second corpus, chosen after the approval
        "-t",
        "-templates",
        "-w",
        "-workflows",
        "-nt",
        "-new-templates",
        # capabilities the risk level was not set for
        "-fuzz",
        "-dast",
        "-code",
        "-headless",
        "-payloads",
        # somewhere else for the traffic or the output to go
        "-proxy",
        "-o",
        "-output",
        "-srd",
        "-store-resp",
        "-store-resp-dir",
        # the response is the only evidence in the record, so it must survive
        "-omit-raw",
        "-or",
        # a record for a request that did not match is not a finding
        "-ms",
        "-matcher-status",
    }
    assert forbidden.isdisjoint(built)
    assert built.count(TARGET) == 1


def test_templates_are_selected_by_identity_and_never_by_path() -> None:
    # A path is a corpus the approval never saw. The contract only accepts ids
    # and tags, so a path cannot be smuggled through either of them.
    paths = (
        "http/cves/2021/CVE-2021-44228.yaml",
        "../../etc/passwd",
        "/opt/mine.yaml",
        "C:/mine.yaml",
    )
    for path in paths:
        with pytest.raises(ValidationError):
            validate_tool_invocation("nuclei", TARGET, {"template_ids": [path]})
        with pytest.raises(ValidationError):
            validate_tool_invocation("nuclei", TARGET, {"tags": [path]})


def test_the_tags_the_argv_cannot_bound_are_always_excluded_and_cannot_be_asked_for() -> None:
    # Excluding them by tag is belt to the argv's braces. Asking for them is a
    # contract error rather than a silently ignored request, because a caller
    # who asked for fuzz templates and got a non-fuzz scan would read the empty
    # result as "nothing found".
    built = argv()
    excluded = built[built.index("-exclude-tags") + 1].split(",")

    assert {"code", "dast", "fuzz", "headless", "js"} <= set(excluded)

    for tag in ("fuzz", "dast", "code", "headless", "js"):
        with pytest.raises(ValidationError):
            validate_tool_invocation("nuclei", TARGET, {"tags": [tag]})


def test_a_caller_s_exclusions_are_added_to_the_mandatory_ones_not_substituted() -> None:
    built = argv(exclude_tags=["dos"])
    excluded = set(built[built.index("-exclude-tags") + 1].split(","))

    assert "dos" in excluded
    assert {"code", "dast", "fuzz", "headless", "js"} <= excluded


def test_the_selection_is_canonical_so_a_replay_digests_the_same() -> None:
    # template_ids is in here deliberately. It was the one canonicaliser in the
    # contract with no coverage: severities and tags were both exercised, so
    # only template_ids could lose its sort and dedupe without a test noticing
    # -- and the consequence is that an approved action replayed with its ids
    # listed in another order is refused as a digest mismatch.
    one = validate_tool_invocation(
        "nuclei",
        TARGET,
        {
            "severities": ["high", "critical", "high"],
            "tags": ["sqli", "rce"],
            "template_ids": ["b-tpl", "a-tpl", "b-tpl"],
        },
    )
    other = validate_tool_invocation(
        "nuclei",
        TARGET,
        {
            "severities": ["critical", "high"],
            "tags": ["rce", "sqli"],
            "template_ids": ["a-tpl", "b-tpl"],
        },
    )

    assert isinstance(one.parameters, NucleiParameters)
    assert one.parameters.severities == ("critical", "high")
    assert one.parameters.template_ids == ("a-tpl", "b-tpl")
    # Without this an approved action replayed with its tags listed in another
    # order is refused as a parameter-digest mismatch.
    assert one.parameter_digest == other.parameter_digest


def test_the_load_is_pinned_well_below_nuclei_s_own_defaults() -> None:
    # nuclei defaults to 150 requests per second with 25 concurrent workers and
    # 30 tolerated host errors, which is more than a fragile production endpoint
    # survives even when the target is the right one.
    built = argv()

    assert built[built.index("-rate-limit") + 1] == "20"
    assert built[built.index("-concurrency") + 1] == "10"
    assert built[built.index("-max-host-error") + 1] == "10"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severities", []),
        ("severities", ["urgent"]),
        ("rate_limit_per_second", 0),
        ("rate_limit_per_second", 151),
        ("concurrency", 0),
        ("concurrency", 51),
        ("bulk_size", 51),
        ("timeout_seconds", 61),
        ("retries", 4),
        ("max_host_error", 31),
    ],
)
def test_out_of_contract_parameters_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        validate_tool_invocation("nuclei", TARGET, {field: value})


@pytest.mark.parametrize(
    "smuggled",
    ["templates", "template_path", "proxy", "headless", "fuzz", "no_interactsh", "output"],
)
def test_an_unknown_parameter_is_refused_rather_than_ignored(smuggled: str) -> None:
    with pytest.raises(ValidationError):
        validate_tool_invocation("nuclei", TARGET, {smuggled: "anything"})


def test_the_worker_environment_requirements_are_stated_in_code() -> None:
    # nuclei reads two inputs argv cannot describe -- $HOME/.config/nuclei/config.yaml,
    # which can set any option including -proxy and -list, and the environment,
    # from which cloud upload arms itself with no flag. So a digest over the
    # parameters does not pin the behaviour on its own. Naming the requirement
    # in code makes it reviewable; leaving it in prose would not.
    assert NUCLEI_WORKER_ENVIRONMENT["HOME"] is not None
    assert NUCLEI_WORKER_ENVIRONMENT["NUCLEI_TEMPLATES_DIR"] is not None
    for scrubbed in ("ENABLE_CLOUD_UPLOAD", "PDCP_API_KEY", "PDCP_TEAM_ID"):
        assert NUCLEI_WORKER_ENVIRONMENT[scrubbed] is None, scrubbed


def test_one_nuclei_run_has_exactly_one_classification() -> None:
    # The manifest's action type is also the ATT&CK key. Declaring
    # "exploit_attempt" here while mitre/techniques.py classifies an observed
    # `nuclei` command line as "vulnerability_scan" meant the same run was
    # labelled T1190 as a tool plan and T1595.002 as a shell transcript, which
    # corrupts the layer comparison the ATT&CK export exists for.
    manifest = get_tool("nuclei")

    assert manifest is not None
    assert manifest.action_type == "vulnerability_scan"
    assert techniques_for_action(manifest.action_type) == ("T1595.002",)


def test_a_vulnerability_scan_cannot_run_without_an_approval() -> None:
    # L1 actions execute automatically on an engagement created with
    # auto_execute_l1. A scan whose template corpus decides what payloads it
    # sends is not something that may start unattended.
    assert classify_risk("vulnerability_scan") is RiskLevel.L2
    assert RiskLevel.L2.requires_approval


def test_the_registry_agrees_that_nuclei_can_actually_run() -> None:
    manifest = get_tool("nuclei")

    assert manifest is not None
    assert manifest.integration_state is IntegrationState.WORKER_READY
    assert build_worker_argv(validate_tool_invocation("nuclei", TARGET, {}))
