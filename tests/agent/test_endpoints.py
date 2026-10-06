"""Tests for endpoint risk classification.

This is a safety gate, not a feature: it decides what an unattended agent is allowed to
call. The cases are drawn from a real endpoint inventory, so a regression here would
let the agent touch something it must not.
"""

from __future__ import annotations

import pytest

from vuln_proof_claw.agent.endpoints import (
    EndpointRisk,
    ProbeStrategy,
    classify_all,
    classify_endpoint,
    probeable,
    refused,
)
from vuln_proof_claw.domain.errors import DomainValidationError

# Taken verbatim from a real platform's bundle.
INVENTORY: tuple[tuple[str, str], ...] = (
    ("GET", "/api/getCompanyDisplay"),
    ("POST", "/api/getUserMenuList"),
    ("POST", "/api/GetAgremmentVersion"),
    ("POST", "/api/getAccountDetail"),
    ("POST", "/api/setDeviceMessage"),
    ("POST", "/api/updateTag"),
    ("POST", "/api/setDeviceSecureWipe"),
    ("POST", "/api/deleteAccount"),
    ("POST", "/api/disableAccountMFA"),
    ("POST", "/api/setDeviceBiosSetting"),
    ("POST", "/api/setDeviceBatchAction"),
    ("POST", "/api/getBootOption"),
)


@pytest.mark.parametrize(
    "path",
    [
        "/api/setDeviceSecureWipe",
        "/api/deleteAccount",
        "/api/disableAccountMFA",
        "/api/setDeviceBiosSetting",
        "/api/setDeviceBatchAction",
        "/api/factoryReset",
        "/api/revokeToken",
        "/api/rebootDevice",
    ],
)
def test_destructive_endpoints_are_never_probed(path: str) -> None:
    """The single most important assertion in this module."""
    result = classify_endpoint("POST", path)

    assert result.risk is EndpointRisk.DESTRUCTIVE
    assert result.strategy is ProbeStrategy.REFUSE
    assert not result.safe_to_probe
    assert not result.risk.probeable_automatically


def test_a_destructive_verb_wins_even_on_a_read_method() -> None:
    """GET /api/resetToken is not a read just because it is a GET."""
    result = classify_endpoint("GET", "/api/resetToken")

    assert result.risk is EndpointRisk.DESTRUCTIVE


def test_a_destructive_verb_wins_over_a_read_verb_in_the_same_path() -> None:
    result = classify_endpoint("POST", "/api/getOrDeleteRecord")

    assert result.risk is EndpointRisk.DESTRUCTIVE


@pytest.mark.parametrize(
    "path",
    ["/api/setDeviceMessage", "/api/updateTag", "/api/createTicket", "/api/uploadFile"],
)
def test_mutating_endpoints_are_probed_with_an_empty_body(path: str) -> None:
    """An incomplete request fails in validation, revealing auth without changing state."""
    result = classify_endpoint("POST", path)

    assert result.risk is EndpointRisk.MUTATING
    assert result.strategy is ProbeStrategy.EMPTY_BODY
    assert result.safe_to_probe


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/getCompanyDisplay"),
        ("GET", "/api/listDevices"),
        ("HEAD", "/api/status"),
        ("GET", "/api/exportReport"),
    ],
)
def test_read_endpoints_are_probed_directly(method: str, path: str) -> None:
    result = classify_endpoint(method, path)

    assert result.risk is EndpointRisk.READ
    assert result.strategy is ProbeStrategy.DIRECT


def test_a_read_exposed_over_post_keeps_its_read_risk_but_a_cautious_strategy() -> None:
    """getUserMenuList is a POST by convention, not because it writes.

    The risk follows the name so an operator sees what it is; the strategy follows the
    method, because a POST may have side effects the name does not advertise.
    """
    result = classify_endpoint("POST", "/api/getUserMenuList")

    assert result.risk is EndpointRisk.READ
    assert result.strategy is ProbeStrategy.EMPTY_BODY
    assert "exposed over POST" in result.reason


def test_an_unrecognised_post_is_assumed_to_write() -> None:
    """Pessimism is the point: an unknown verb must not be probed as a read."""
    result = classify_endpoint("POST", "/api/frobnicate")

    assert result.risk is EndpointRisk.MUTATING
    assert result.strategy is ProbeStrategy.EMPTY_BODY
    assert "assumed to write" in result.reason


def test_an_unrecognised_get_is_treated_as_a_read() -> None:
    result = classify_endpoint("GET", "/api/frobnicate")

    assert result.risk is EndpointRisk.READ


@pytest.mark.parametrize(("method", "path"), [("", "/x"), ("GET", "relative/path")])
def test_malformed_input_is_refused(method: str, path: str) -> None:
    with pytest.raises(DomainValidationError):
        classify_endpoint(method, path)


def test_a_real_inventory_splits_as_expected() -> None:
    classifications = classify_all(INVENTORY)
    allowed = probeable(classifications)
    held = refused(classifications)

    assert len(classifications) == len(INVENTORY)
    assert {item.path for item in held} == {
        "/api/setDeviceSecureWipe",
        "/api/deleteAccount",
        "/api/disableAccountMFA",
        "/api/setDeviceBiosSetting",
        "/api/setDeviceBatchAction",
        "/api/getBootOption",
    }
    assert "/api/setDeviceMessage" in {item.path for item in allowed}
    assert "/api/getCompanyDisplay" in {item.path for item in allowed}


def test_held_endpoints_are_reported_not_dropped() -> None:
    """These are the most interesting endpoints; an operator must see them."""
    held = refused(classify_all(INVENTORY))

    for item in held:
        assert item.reason
        assert "destructive verb" in item.reason
        assert item.as_summary().startswith("[destructive")


def test_classification_is_order_preserving() -> None:
    classifications = classify_all(INVENTORY)

    assert [item.path for item in classifications] == [path for _, path in INVENTORY]


def test_a_delete_is_destructive_whatever_the_path_is_called() -> None:
    """Observed live: DELETE /web/vans/blacklist read as a list, because "blacklist"
    contains "list".

    A name is a hint; a method is a fact. The hint was lowering the risk, which is the
    direction that gets something called that should not have been.
    """
    classified = classify_endpoint("DELETE", "/web/vans/blacklist")

    assert classified.risk is EndpointRisk.DESTRUCTIVE
    assert classified.strategy is ProbeStrategy.REFUSE


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_a_replace_is_mutating_whatever_the_path_is_called(method: str) -> None:
    classified = classify_endpoint(method, "/web/clients/list")

    assert classified.risk is EndpointRisk.MUTATING
    assert classified.strategy is ProbeStrategy.EMPTY_BODY


def test_a_method_only_sets_a_floor() -> None:
    """GET and POST say nothing on their own, so those stay judged by the name."""
    assert classify_endpoint("GET", "/api/resetToken").risk is EndpointRisk.DESTRUCTIVE
    assert classify_endpoint("POST", "/api/getUserMenuList").risk is EndpointRisk.READ
