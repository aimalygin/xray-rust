#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub path: Option<String>,
    pub message: String,
}

impl Diagnostic {
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            path: Some(path.into()),
            message: message.into(),
        }
    }

    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Warning,
            path: Some(path.into()),
            message: message.into(),
        }
    }
}
