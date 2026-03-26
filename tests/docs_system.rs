use std::fs;
use std::path::Path;

const REQUIRED_DOC_FILES: &[&str] = &[
    "AGENTS.md",
    "docs/README.md",
    "docs/docs-system-map.md",
    "docs/architecture/system-boundaries.md",
    "docs/architecture/source-layout.md",
    "docs/src/index.md",
    "docs/src/policy.md",
    "docs/src/http-api.md",
    "docs/src/SUMMARY.md",
];

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn required_doc_files_exist() {
    for relative_path in REQUIRED_DOC_FILES {
        assert!(
            repo_root().join(relative_path).exists(),
            "missing required doc file: {relative_path}"
        );
    }
}

#[test]
fn readme_and_agents_point_to_doc_entrypoints() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let agents = fs::read_to_string(repo_root().join("AGENTS.md")).expect("read AGENTS.md");

    assert!(readme.contains("docs/README.md"));
    assert!(readme.contains("docs/docs-system-map.md"));
    assert!(agents.contains("docs/docs-system-map.md"));
    assert!(agents.contains("docs/src/policy.md"));
}
