pub mod anthropic;
pub mod mistral;
pub mod models;
pub mod ollama;
pub mod openai;
pub mod openai_compatible;
pub mod openrouter;
pub mod orcarouter;
pub mod ovhcloud;
// pub mod mistral_native; // TODO: Complete implementation

#[cfg(test)]
pub(crate) mod tests;
