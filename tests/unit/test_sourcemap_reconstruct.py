"""Unit tests for source-map reconstruction (pure)."""

from __future__ import annotations

from webrecon.modules.javascript.sourcemap import parse_source_map, reconstruct_sources

_MAP = (
    '{"version":3,"sources":["a.js","b.js"],'
    '"sourcesContent":["const x=1;","fetch(\\"/api/me\\");"],'
    '"names":[],"mappings":"AAAA"}'
)


def test_parse_detects_sources_content() -> None:
    info = parse_source_map(_MAP)
    assert info is not None and info.has_sources_content is True
    assert info.sources_count == 2


def test_reconstruct_pairs_path_and_content() -> None:
    files = reconstruct_sources(_MAP)
    assert files == [("a.js", "const x=1;"), ("b.js", 'fetch("/api/me");')]


def test_reconstruct_no_content() -> None:
    assert reconstruct_sources('{"version":3,"sources":["a.js"],"mappings":""}') == []


def test_reconstruct_bad_json() -> None:
    assert reconstruct_sources("not json") == []


def test_reconstruct_caps_file_count() -> None:
    srcs = ",".join(f'"f{i}.js"' for i in range(60))
    contents = ",".join('"x"' for _ in range(60))
    doc = f'{{"version":3,"sources":[{srcs}],"sourcesContent":[{contents}],"mappings":""}}'
    assert len(reconstruct_sources(doc, max_files=50)) == 50
