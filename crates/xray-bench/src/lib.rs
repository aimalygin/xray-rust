use thiserror::Error;

#[derive(Debug, Error)]
pub enum BenchError {
    #[error("{0}")]
    InvalidArguments(String),
}

pub async fn run_cli<I, S>(_args: I) -> Result<(), BenchError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Err(BenchError::InvalidArguments(
        "usage: xray-bench run|compare [options]".to_owned(),
    ))
}
