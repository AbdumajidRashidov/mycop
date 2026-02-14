use tree_sitter::Language;

/// Get the tree-sitter Python language
pub fn language() -> Language {
    tree_sitter_python::LANGUAGE.into()
}
