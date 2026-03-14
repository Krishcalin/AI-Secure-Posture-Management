# Intentionally vulnerable Terraform for AI-SPM v1.1.0 testing

# AISPM-IAC-001: SageMaker without VPC/encryption
resource "aws_sagemaker_endpoint" "model_endpoint" {
  name                 = "prod-llm-endpoint"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.config.name
}

# AISPM-IAC-002: Bedrock without IAM conditions
resource "aws_iam_policy" "bedrock_access" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "bedrock:*"
      Resource = "*"
    }]
  })
}

# AISPM-IAC-003: Vertex AI without private networking
resource "google_notebooks_instance" "ml_notebook" {
  name         = "ml-dev-notebook"
  machine_type = "n1-standard-8"
  location     = "us-central1-a"
}

# AISPM-IAC-004: Azure OpenAI with key-based auth
resource "azurerm_cognitive_account" "openai" {
  name     = "prod-openai"
  kind     = "OpenAI"
  sku_name = "S0"
  api_key  = var.openai_api_key
}

# AISPM-IAC-005: Public model bucket
resource "aws_s3_bucket" "training_data" {
  bucket = "ml-training-dataset"
  acl    = "public-read"
}
