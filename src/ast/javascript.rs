use tree_sitter::Language;

/// Get the tree-sitter JavaScript language
pub fn js_language() -> Language {
    tree_sitter_javascript::LANGUAGE.into()
}

/// Get the tree-sitter TypeScript language
pub fn ts_language() -> Language {
    tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
}
