# OBELISK AWS Variables

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "allowed_cidr_blocks" {
  description = "Allowed CIDR blocks for API access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "domain_name" {
  description = "Domain name for OBELISK"
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.xlarge"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 100
}

variable "db_max_allocated_storage" {
  description = "RDS max allocated storage in GB"
  type        = number
  default     = 1000
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "obelisk"
}

variable "db_username" {
  description = "Database username"
  type        = string
  default     = "obelisk_admin"
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "redis_auth_token" {
  description = "Redis auth token"
  type        = string
  sensitive   = true
}

variable "task_cpu" {
  description = "ECS task CPU units"
  type        = number
  default     = 2048
}

variable "task_memory" {
  description = "ECS task memory in MiB"
  type        = number
  default     = 4096
}

variable "desired_count" {
  description = "Desired ECS task count"
  type        = number
  default     = 3
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "rate_limit" {
  description = "WAF rate limit per 5 minutes"
  type        = number
  default     = 2000
}

variable "enable_hsm" {
  description = "Enable CloudHSM"
  type        = bool
  default     = false
}

variable "hsm_count" {
  description = "Number of HSMs to provision"
  type        = number
  default     = 2
}

variable "hsm_eni_id" {
  description = "HSM ENI ID"
  type        = string
  default     = ""
}

variable "backup_retention_days" {
  description = "RDS backup retention in days"
  type        = number
  default     = 35
}
