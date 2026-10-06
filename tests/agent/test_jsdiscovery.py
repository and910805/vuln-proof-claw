"""Tests for recovering an API inventory from client-side JavaScript.

The fixtures are shaped after bundles actually served by two different targets — a Vite
build and a webpack build — because a parser that only handles invented input is a
parser that fails on the first real site.
"""

from __future__ import annotations

import pytest

from vuln_proof_claw.agent.endpoints import classify_all
from vuln_proof_claw.agent.jsdiscovery import (
    extract_assets,
    extract_calls,
    extract_chunk_table,
    inventory,
    parameterised,
)

VITE_HTML = """<!doctype html>
<html lang="en">
  <head>
    <title>Admyn Official</title>
    <script type="module" crossorigin src="/assets/index-Bpi7DfT9.js"></script>
    <link rel="modulepreload" crossorigin href="/assets/vendor-CttiFUl-.js">
    <link rel="modulepreload" crossorigin href="/assets/primevue-DEXvLW9i.js">
    <link rel="stylesheet" crossorigin href="/assets/index-BJJ1C33Q.css">
  </head>
  <body><div id="app"></div><script src="/runtime-config.js"></script></body>
</html>"""

# The axios-wrapper shape, as served by the Vite target.
VITE_BUNDLE = """
function a(e){return r({url:"/api/getUserMenuList",method:"post",data:e})}
function b(e){return r({url:"/api/setDeviceMessage",method:"post",data:e})}
function c(e){return r({url:"/api/setDeviceSecureWipe",method:"post",data:e})}
var d=`/api/getCompanyDisplay?adminUuid=${t}`;
function f(e){return n.get(`/api/companies/${e.id}/members`)}
function g(){return n.delete("/api/deleteAccount")}
"""

# The .concat() shape, as served by the webpack target.
WEBPACK_BUNDLE = """
function f(e){return(0,r.A)({url:"/web/policy-groups/".concat(e.groupId),method:"PUT",data:e})}
function h(e){return(0,r.A)({url:"/web/policy-groups/".concat(e),method:"GET"})}
function v(e){return(0,r.A)({url:"/web/pkghub/files/".concat(t,"/convert"),method:"POST"})}
"""

WEBPACK_RUNTIME = (
    'f.u=function(e){return({837:"vendor-charts",4223:"commons",8096:"vendors"}[e]||e)'
    '+"."+{27:"95dfb3a6360c85380083",4223:"3b25d8db336b9de057d4",'
    '8096:"a1e5e97236d6d7103177"}[e]+".chunk.js"}'
)


def test_scripts_and_preloads_are_both_found() -> None:
    """Vite puts the application entry in a script and its chunks in preloads."""
    assets = extract_assets(VITE_HTML)

    assert "/assets/index-Bpi7DfT9.js" in assets.scripts
    assert "/runtime-config.js" in assets.scripts
    assert "/assets/vendor-CttiFUl-.js" in assets.preloads
    assert "/assets/primevue-DEXvLW9i.js" in assets.preloads


def test_stylesheets_are_not_mistaken_for_scripts() -> None:
    assets = extract_assets(VITE_HTML)

    assert all(not item.endswith(".css") for item in assets.all)


def test_assets_are_deduplicated_and_ordered() -> None:
    assets = extract_assets(VITE_HTML + VITE_HTML)

    assert len(assets.all) == len(set(assets.all))


def test_the_request_config_shape_is_recovered() -> None:
    calls = extract_calls(VITE_BUNDLE)
    found = {(call.method, call.path) for call in calls}

    assert ("POST", "/api/getUserMenuList") in found
    assert ("POST", "/api/setDeviceMessage") in found
    assert ("POST", "/api/setDeviceSecureWipe") in found


def test_the_direct_call_shape_is_recovered() -> None:
    calls = extract_calls(VITE_BUNDLE)
    found = {(call.method, call.path) for call in calls}

    assert ("GET", "/api/companies/{param}/members") in found
    assert ("DELETE", "/api/deleteAccount") in found


def test_the_concat_shape_is_recovered_with_its_parameter() -> None:
    """The webpack target builds paths by concatenation rather than interpolation.

    Without recovering the parameter these all look like static routes, and no IDOR
    candidate on a webpack-built application would ever be surfaced.
    """
    calls = extract_calls(WEBPACK_BUNDLE)
    found = {(call.method, call.path) for call in calls}

    assert ("PUT", "/web/policy-groups/{param}") in found
    assert ("GET", "/web/policy-groups/{param}") in found
    assert ("POST", "/web/pkghub/files/{param}/convert") in found


def test_concat_built_paths_are_marked_parameterised() -> None:
    candidates = {call.path for call in parameterised(extract_calls(WEBPACK_BUNDLE))}

    assert "/web/policy-groups/{param}" in candidates
    assert "/web/pkghub/files/{param}/convert" in candidates


def test_template_interpolation_becomes_a_parameter_marker() -> None:
    calls = extract_calls(VITE_BUNDLE)
    members = next(call for call in calls if "members" in call.path)

    assert members.path == "/api/companies/{param}/members"
    assert members.parameterised


def test_parameterised_calls_are_separable() -> None:
    """These are where an ownership check is most often missing."""
    candidates = parameterised(extract_calls(VITE_BUNDLE))

    assert {call.path for call in candidates} == {"/api/companies/{param}/members"}


def test_results_are_deduplicated_and_stable() -> None:
    once = extract_calls(VITE_BUNDLE)
    twice = extract_calls(VITE_BUNDLE + VITE_BUNDLE)

    assert once == twice
    assert len(once) == len({(call.method, call.path) for call in once})


def test_relative_and_malformed_paths_are_ignored() -> None:
    calls = extract_calls(
        'r({url:"not-a-path",method:"get"});r({url:"' + "/x" * 200 + '",method:"get"})'
    )

    assert calls == ()


def test_the_webpack_chunk_table_is_recovered() -> None:
    """Application code lives in lazy chunks; without these the inventory is libraries."""
    table = extract_chunk_table(WEBPACK_RUNTIME)
    names = table.filenames()

    assert table.suffix == ".chunk.js"
    assert "commons.3b25d8db336b9de057d4.chunk.js" in names
    assert "vendors.a1e5e97236d6d7103177.chunk.js" in names
    assert "27.95dfb3a6360c85380083.chunk.js" in names


def test_a_runtime_without_a_chunk_table_yields_nothing() -> None:
    table = extract_chunk_table("console.log('hello')")

    assert table.entries == ()
    assert table.filenames() == ()


def test_the_inventory_is_shaped_for_the_classifier() -> None:
    pairs = inventory(extract_calls(VITE_BUNDLE))
    classifications = classify_all(pairs)

    assert len(classifications) == len(pairs)
    held = {item.path for item in classifications if not item.safe_to_probe}
    assert "/api/setDeviceSecureWipe" in held
    assert "/api/deleteAccount" in held


@pytest.mark.parametrize("source", ["", "// nothing here", "{}"])
def test_an_empty_bundle_is_handled(source: str) -> None:
    assert extract_calls(source) == ()
    assert extract_assets(source).all == ()
