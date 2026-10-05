"""Tests for action-type to ATT&CK technique mapping and command classification."""

from __future__ import annotations

import pytest

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.mitre.techniques import (
    ACTION_TECHNIQUES,
    TECHNIQUE_NAMES,
    classify_command,
    request_parts,
    targets_the_engagement,
    techniques_for_action,
)
from vuln_proof_claw.policy.risk import ACTION_RISK_LEVELS, classify_risk


def test_every_mapped_action_type_is_a_known_policy_action() -> None:
    assert set(ACTION_TECHNIQUES) == set(ACTION_RISK_LEVELS)


def test_every_referenced_technique_has_a_name() -> None:
    referenced = {
        technique for techniques in ACTION_TECHNIQUES.values() for technique in techniques
    }
    assert referenced <= set(TECHNIQUE_NAMES)


def test_a_vulnerability_scan_needs_an_approval_before_it_runs() -> None:
    # Was L1 here, which was wrong in a way that mattered: L1 actions execute
    # automatically on an engagement created with auto_execute_l1. The L1 group
    # is probing -- enumerate paths, connect to ports, read an API. A
    # vulnerability scan sends exploit-shaped payloads chosen by a template
    # corpus, so it belongs with the actions an operator accepts in advance.
    assert classify_risk("vulnerability_scan") is RiskLevel.L2
    assert RiskLevel.L2.requires_approval
    # The ATT&CK classification is unchanged: scanning is reconnaissance
    # regardless of the approval it needs.
    assert techniques_for_action("vulnerability_scan") == ("T1595.002",)


def test_action_lookup_normalizes_and_falls_back_to_empty() -> None:
    assert techniques_for_action("Directory Enumeration") == ("T1595.003",)
    assert techniques_for_action("no_such_action") == ()


@pytest.mark.parametrize(
    ("command", "action_type", "technique"),
    [
        ("curl 'http://s/ajax.php?file=../wp-config.php'", "post_exploitation", "T1552.001"),
        ("curl 'http://site/x?file=../../../../etc/passwd'", "post_exploitation", "T1083"),
        ("nuclei -u http://site -t wordpress/", "vulnerability_scan", "T1595.002"),
        ("ffuf -w list.txt -u http://site/FUZZ", "directory_enumeration", "T1595.003"),
        ("nmap -sV -p 80 site", "port_scan", "T1595.001"),
        ("httpx -u http://site", "passive_fingerprint", "T1592.002"),
        ("hydra -l admin -P pw.txt site http-post-form", "password_test", "T1110.001"),
        ("curl http://site/xmlrpc.php -d '<methodCall/>'", "destructive_operation", "T1499.002"),
        ("curl http://site/robots.txt", "robots_read", "T1594"),
        ("curl -s http://site/wp-json/", "public_page_read", "T1594"),
        ("curl http://site/openapi.json", "passive_discovery", "T1594"),
    ],
)
def test_command_classification(command: str, action_type: str, technique: str) -> None:
    classification = classify_command(command)
    assert classification is not None
    assert classification.action_type == action_type
    assert technique in classification.techniques


def test_shell_payload_reports_both_exploit_and_shell_execution() -> None:
    classification = classify_command(
        "curl --get --data-urlencode 'host=127.0.0.1;id' http://site/wp-json/netcheck/v1/probe"
    )
    assert classification is not None
    assert classification.action_type == "exploit_attempt"
    assert classification.techniques == ("T1190", "T1059.004")


def test_credential_read_outranks_a_plain_page_read() -> None:
    classification = classify_command("curl http://site/.env")
    assert classification is not None
    assert classification.techniques == ("T1552.001",)


@pytest.mark.parametrize("command", ["", "   ", "echo hello", "sleep 5"])
def test_unclassifiable_commands_return_none(command: str) -> None:
    assert classify_command(command) is None


def test_ordinary_command_substitution_is_not_an_exploit() -> None:
    # Real transcripts are full of this. Reading it as a shell-injection payload
    # turned 160 routine commands into exploit attempts.
    assert classify_command("cd $(git rev-parse --show-toplevel) && ls") is None
    assert classify_command("docker rm -f $(docker ps -aq)") is None


def test_a_local_shell_chain_without_a_url_is_not_classified() -> None:
    assert classify_command("cat /etc/hosts; id") is None


def test_the_same_payload_over_http_is_classified() -> None:
    classification = classify_command("curl 'http://site/probe?host=127.0.0.1;id'")
    assert classification is not None
    assert classification.action_type == "exploit_attempt"


def test_reading_a_local_env_file_is_not_credential_access_on_the_target() -> None:
    assert classify_command("cat .env") is None


def test_target_scoping_drops_commands_aimed_elsewhere() -> None:
    lab_setup = "curl -s http://registry.npmjs.org/strix-agent"
    assert classify_command(lab_setup) is not None
    assert classify_command(lab_setup, targets=["site-c"]) is None


def test_target_scoping_keeps_commands_aimed_at_the_target() -> None:
    classification = classify_command(
        "nuclei -u http://site-c -t wordpress/", targets=["site-c", "site-d"]
    )
    assert classification is not None
    assert classification.action_type == "vulnerability_scan"


def test_target_matching_ignores_case() -> None:
    assert targets_the_engagement("curl http://SITE-C/wp-json/", ["site-c"])


def test_a_target_list_of_only_blanks_is_an_error_not_a_silent_drop() -> None:
    with pytest.raises(ValueError, match="none of them are usable"):
        targets_the_engagement("curl http://site-c/", ["   ", ""])


def test_a_tool_inventory_loop_is_not_a_scan() -> None:
    # Counting mentions credited a run with a wpscan it never executed.
    assert classify_command("for t in curl nmap wpscan; do command -v $t; done") is None
    assert classify_command("command -v nuclei") is None


def test_a_version_check_is_not_a_scan() -> None:
    assert classify_command("wpscan --version") is None
    assert classify_command("nuclei -version") is None


def test_prose_mentioning_a_tool_is_not_a_scan() -> None:
    assert classify_command("echo 'compare the nuclei output against the log'") is None


def test_a_real_invocation_counts() -> None:
    for command in (
        "wpscan --url http://site-c --enumerate p",
        "/usr/bin/nuclei -u http://site-c -t wordpress/",
        'NMAP="/c/Program Files/nmap.exe"; "$NMAP" -sV -p80 site-c',
        "docker exec box ffuf -w list -u http://site-c/FUZZ",
    ):
        assert classify_command(command) is not None, command


def test_a_python_snippet_building_a_traversal_is_not_a_request() -> None:
    assert classify_command("python -c \"print('../'*3 + 'etc/passwd')\"") is None


def test_request_parts_reads_the_url_and_the_data_argument() -> None:
    parts = request_parts(
        "curl --get --data-urlencode 'host=127.0.0.1;id' http://site-d/probe"
    )
    assert "http://site-d/probe" in parts
    assert "host=127.0.0.1;id" in parts


def test_request_parts_ignores_quotes_without_a_body_flag() -> None:
    assert request_parts("cat > 'x;id' && curl http://site-d/") == ("http://site-d/",)


def test_a_hand_written_client_passing_only_a_path_is_still_a_request() -> None:
    # An agent that outgrows curl writes its own client, putting the host in
    # code and passing the path as an argument. There is no http:// to find.
    classification = classify_command(
        'python3 raw.py "/?action=duplicator_download&file=../../../../etc/passwd"'
    )
    assert classification is not None
    assert classification.techniques == ("T1083",)


def test_a_local_path_without_a_query_is_not_a_request() -> None:
    assert classify_command("ls /usr/share/wordlists/dirb") is None
    assert classify_command("rm -rf /tmp/hs8092") is None
