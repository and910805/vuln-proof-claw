"""Tests for building a Navigator layer from Claude Code stream transcripts."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.attck_layer import main, observe_run, read_invocations

from vuln_proof_claw.mitre.layer import Outcome


def tool_use(identifier: str, command: str) -> dict[str, object]:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": identifier,
                    "name": "Bash",
                    "input": {"command": command},
                }
            ]
        },
    }


def tool_result(identifier: str, output: str) -> dict[str, object]:
    return {
        "type": "user",
        "message": {
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": identifier,
                    "content": [{"type": "text", "text": output}],
                }
            ]
        },
    }


def write_transcript(directory: Path, records: list[dict[str, object]]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "stream.jsonl"
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )
    return path


def test_tool_calls_are_paired_with_their_results(tmp_path: Path) -> None:
    path = write_transcript(
        tmp_path / "hs-site-a",
        [
            tool_use("a1", "nuclei -u http://site"),
            tool_result("a1", "found nothing"),
            tool_use("a2", "ffuf -w list -u http://site/FUZZ"),
        ],
    )
    invocations, unpaired = read_invocations(path)
    assert [item.command for item in invocations] == ["nuclei -u http://site"]
    assert unpaired == 1


def test_malformed_and_blank_lines_are_skipped(tmp_path: Path) -> None:
    directory = tmp_path / "hs-site-b"
    directory.mkdir()
    path = directory / "stream.jsonl"
    payload = json.dumps(tool_use("b1", "nmap -p 80 site"))
    result = json.dumps(tool_result("b1", "80/tcp open"))
    path.write_text(f"\n{{not json\n{payload}\n\n{result}\n", encoding="utf-8")
    invocations, unpaired = read_invocations(path)
    assert len(invocations) == 1
    assert unpaired == 0


def test_blank_result_is_recorded_as_a_silent_failure(tmp_path: Path) -> None:
    path = write_transcript(
        tmp_path / "hs-site-b",
        [
            tool_use("b1", "feroxbuster -u http://site -x php"),
            tool_result("b1", ""),
        ],
    )
    tally = observe_run(path, run="site-b", evidence_techniques=frozenset())
    assert tally.unmatched == []
    assert [item.outcome for item in tally.observations] == [Outcome.SILENT_FAILURE]


def test_unclassified_commands_are_reported_not_dropped(tmp_path: Path) -> None:
    path = write_transcript(
        tmp_path / "hs-site-c",
        [tool_use("c1", "echo hello"), tool_result("c1", "hello")],
    )
    tally = observe_run(path, run="site-c", evidence_techniques=frozenset())
    assert tally.observations == []
    assert tally.unmatched == ["echo hello"]


def test_end_to_end_layer_has_evidence_declined_and_tracked_cells(tmp_path: Path) -> None:
    path = write_transcript(
        tmp_path / "hs-site-d",
        [
            tool_use("d1", "curl --get --data-urlencode 'host=127.0.0.1;id' http://site/probe"),
            tool_result("d1", "uid=33(www-data)"),
        ],
    )
    output = tmp_path / "layer.json"
    code = main(
        [
            str(path),
            "--name",
            "site-d",
            "--evidence",
            "T1190",
            "--declined",
            "T1499.002=judged destructive",
            "--track",
            "T1505.003",
            "--out",
            str(output),
        ]
    )
    assert code == 0
    layer = json.loads(output.read_text(encoding="utf-8"))
    entries = {entry["techniqueID"]: entry for entry in layer["techniques"]}
    assert entries["T1190"]["score"] == Outcome.POSITIVE.score
    assert entries["T1059.004"]["score"] == Outcome.NEGATIVE.score
    assert entries["T1499.002"]["score"] == Outcome.DECLINED.score
    assert entries["T1505.003"]["score"] == Outcome.NOT_ATTEMPTED.score
    assert layer["description"].endswith("Runs: hs-site-d.")


def test_missing_transcript_fails_without_writing_a_layer(tmp_path: Path) -> None:
    assert main([str(tmp_path / "absent" / "stream.jsonl")]) == 2


def test_a_structured_result_saying_it_did_not_time_out_is_not_a_timeout(tmp_path: Path) -> None:
    # Every successful call from a structured tool server carries this field.
    # Matching the field name marked all of them as timed out.
    path = write_transcript(
        tmp_path / "hs-site-d",
        [
            tool_use("d1", "curl http://site-d/wp-json/"),
            tool_result(
                "d1",
                '{"result":{"timed_out":false,"return_code":0,"stdout":"{\\"name\\":\\"Blog\\"}"}}',
            ),
        ],
    )
    invocations, _ = read_invocations(path)
    assert invocations[0].timed_out is False


def test_a_structured_result_reporting_a_timeout_is_a_timeout(tmp_path: Path) -> None:
    path = write_transcript(
        tmp_path / "hs-site-b",
        [
            tool_use("b1", "feroxbuster -u http://site-b -x php"),
            tool_result("b1", '{"result":{"timed_out":true,"return_code":-1,"stdout":""}}'),
        ],
    )
    invocations, _ = read_invocations(path)
    assert invocations[0].timed_out is True


def test_out_of_scope_commands_are_counted_apart_from_unmatched(tmp_path: Path) -> None:
    # One number for both would hide a real gap in the signature table behind
    # the large pile of setup commands that were correctly skipped.
    path = write_transcript(
        tmp_path / "hs-site-c",
        [
            tool_use("c1", "docker ps -a"),
            tool_result("c1", "CONTAINER ID"),
            tool_use("c2", "echo hello site-c"),
            tool_result("c2", "hello"),
            tool_use("c3", "nuclei -u http://site-c -t wordpress/"),
            tool_result("c3", "[INF] no results"),
        ],
    )
    tally = observe_run(
        path, run="site-c", evidence_techniques=frozenset(), targets=["site-c"]
    )
    assert tally.out_of_scope == 1
    assert tally.unmatched == ["echo hello site-c"]
    assert len(tally.observations) == 1


def test_evidence_can_be_scoped_to_one_run(tmp_path: Path) -> None:
    # A technique confirmed on site-d was not confirmed on site-a. Applying one
    # global flag would credit the clean run with a finding it never made.
    for run, target in (("hs-site-a", "site-a"), ("hs-site-d", "site-d")):
        write_transcript(
            tmp_path / run,
            [
                tool_use("x1", f"curl 'http://{target}/probe?host=127.0.0.1;id'"),
                tool_result("x1", "uid=33(www-data)"),
            ],
        )
    output = tmp_path / "layer.json"
    code = main(
        [
            str(tmp_path / "hs-site-a" / "stream.jsonl"),
            str(tmp_path / "hs-site-d" / "stream.jsonl"),
            "--evidence",
            "hs-site-d:T1190",
            "--out",
            str(output),
        ]
    )
    assert code == 0
    entry = next(
        item
        for item in json.loads(output.read_text(encoding="utf-8"))["techniques"]
        if item["techniqueID"] == "T1190"
    )
    recorded = {item["name"]: item["value"] for item in entry["metadata"]}
    assert recorded["hs-site-d"].startswith("positive")
    assert recorded["hs-site-a"].startswith("negative")


def test_unprefixed_evidence_still_applies_to_every_run(tmp_path: Path) -> None:
    for run in ("hs-one", "hs-two"):
        write_transcript(
            tmp_path / run,
            [
                tool_use("y1", "curl 'http://site/probe?host=1;id'"),
                tool_result("y1", "uid=33"),
            ],
        )
    output = tmp_path / "layer.json"
    assert (
        main(
            [
                str(tmp_path / "hs-one" / "stream.jsonl"),
                str(tmp_path / "hs-two" / "stream.jsonl"),
                "--evidence",
                "T1190",
                "--out",
                str(output),
            ]
        )
        == 0
    )
    entry = next(
        item
        for item in json.loads(output.read_text(encoding="utf-8"))["techniques"]
        if item["techniqueID"] == "T1190"
    )
    assert all(item["value"].startswith("positive") for item in entry["metadata"])


def test_a_declined_note_can_be_scoped_to_one_run(tmp_path: Path) -> None:
    for run in ("hs-clean", "hs-vuln"):
        write_transcript(
            tmp_path / run,
            [tool_use("z1", "curl http://site/"), tool_result("z1", "ok")],
        )
    output = tmp_path / "layer.json"
    assert (
        main(
            [
                str(tmp_path / "hs-clean" / "stream.jsonl"),
                str(tmp_path / "hs-vuln" / "stream.jsonl"),
                "--declined",
                "hs-vuln:T1499.002=judged destructive",
                "--out",
                str(output),
            ]
        )
        == 0
    )
    entry = next(
        item
        for item in json.loads(output.read_text(encoding="utf-8"))["techniques"]
        if item["techniqueID"] == "T1499.002"
    )
    assert [item["name"] for item in entry["metadata"]] == ["hs-vuln"]
