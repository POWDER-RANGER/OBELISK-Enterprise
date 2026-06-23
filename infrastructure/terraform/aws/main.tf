# OBELISK Enterprise — AWS Terraform Module
# Multi-AZ deployment with VPC, ECS Fargate, RDS, ElastiCache, and HSM
# terraform init && terraform plan && terraform apply

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "obelisk-terraform-state"
    key            = "obelisk/aws/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "obelisk-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "OBELISK"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# VPC with public/private subnets across 3 AZs
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "obelisk-${var.environment}"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment == "production" ? false : true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  enable_flow_log        = true
}

# Security Groups
resource "aws_security_group" "obelisk_api" {
  name_prefix = "obelisk-api-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "obelisk_hsm" {
  name_prefix = "obelisk-hsm-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 2223
    to_port         = 2225
    protocol        = "tcp"
    security_groups = [aws_security_group.obelisk_api.id]
  }

  tags = {
    Name = "obelisk-hsm-sg"
  }
}

# ECS Cluster with Fargate
resource "aws_ecs_cluster" "obelisk" {
  name = "obelisk-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "obelisk" {
  cluster_name = aws_ecs_cluster.obelisk.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 1
    capacity_provider = "FARGATE"
  }
}

# KMS Keys
resource "aws_kms_key" "obelisk" {
  description             = "OBELISK data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true
}

resource "aws_kms_alias" "obelisk" {
  name          = "alias/obelisk-${var.environment}"
  target_key_id = aws_kms_key.obelisk.key_id
}

data "aws_caller_identity" "current" {}

# IAM Roles
resource "aws_iam_role" "ecs_execution" {
  name = "obelisk-ecs-execution-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "obelisk-ecs-task-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# Secrets Manager
resource "aws_secretsmanager_secret" "obelisk" {
  name                    = "obelisk/${var.environment}"
  description             = "OBELISK configuration secrets"
  kms_key_id              = aws_kms_key.obelisk.arn
  recovery_window_in_days = 30
}

# CloudHSM Cluster
resource "aws_cloudhsm_v2_cluster" "obelisk" {
  count          = var.enable_hsm ? 1 : 0
  hsm_eni_id     = var.hsm_eni_id
  subnet_ids     = module.vpc.private_subnets
  security_group_ids = [aws_security_group.obelisk_hsm.id]
}

# Application Load Balancer
resource "aws_lb" "obelisk" {
  name               = "obelisk-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.obelisk_api.id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = var.environment == "production"
  enable_http2               = true
}

# RDS PostgreSQL
resource "aws_db_subnet_group" "obelisk" {
  name       = "obelisk-${var.environment}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "obelisk" {
  identifier     = "obelisk-${var.environment}"
  engine         = "postgres"
  engine_version = "16.1"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.obelisk.arn

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  vpc_security_group_ids = [aws_security_group.obelisk_db.id]
  db_subnet_group_name   = aws_db_subnet_group.obelisk.name

  multi_az               = var.environment == "production"
  publicly_accessible    = false
  deletion_protection    = var.environment == "production"
  skip_final_snapshot    = var.environment != "production"

  backup_retention_period = var.backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  enabled_cloudwatch_logs_exports = ["postgresql"]

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.obelisk.arn
}

resource "aws_security_group" "obelisk_db" {
  name_prefix = "obelisk-db-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.obelisk_api.id]
  }
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "obelisk" {
  name       = "obelisk-${var.environment}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "obelisk" {
  replication_group_id = "obelisk-${var.environment}"
  description          = "OBELISK session and cache store"

  node_type            = var.redis_node_type
  num_cache_clusters   = var.environment == "production" ? 3 : 1
  automatic_failover_enabled = var.environment == "production"
  multi_az_enabled     = var.environment == "production"

  at_rest_encryption_enabled = true
  kms_key_id                = aws_kms_key.obelisk.arn
  transit_encryption_enabled = true
  auth_token                = var.redis_auth_token

  subnet_group_name  = aws_elasticache_subnet_group.obelisk.name
  security_group_ids = [aws_security_group.obelisk_redis.id]
}

resource "aws_security_group" "obelisk_redis" {
  name_prefix = "obelisk-redis-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.obelisk_api.id]
  }
}

# ECR Repository
resource "aws_ecr_repository" "obelisk" {
  name                 = "obelisk-${var.environment}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.obelisk.arn
  }
}

# ECS Service
resource "aws_ecs_service" "obelisk" {
  name            = "obelisk-${var.environment}"
  cluster         = aws_ecs_cluster.obelisk.id
  task_definition = aws_ecs_task_definition.obelisk.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [aws_security_group.obelisk_api.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.obelisk_api.arn
    container_name   = "obelisk-api"
    container_port   = 8443
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}

resource "aws_ecs_task_definition" "obelisk" {
  family                   = "obelisk-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "obelisk-api"
      image = "${aws_ecr_repository.obelisk.repository_url}:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 8443
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "OBELISK_ENV", value = var.environment },
        { name = "OBELISK_REGION", value = var.aws_region },
        { name = "DB_HOST", value = aws_db_instance.obelisk.address },
        { name = "DB_NAME", value = var.db_name },
        { name = "REDIS_HOST", value = aws_elasticache_replication_group.obelisk.primary_endpoint_address },
        { name = "HSM_ENABLED", value = tostring(var.enable_hsm) },
        { name = "KMS_KEY_ID", value = aws_kms_key.obelisk.arn }
      ]
      secrets = [
        {
          name      = "DB_PASSWORD"
          valueFrom = aws_secretsmanager_secret.obelisk.arn
        }
      ]
    }
  ])
}

resource "aws_lb_target_group" "obelisk_api" {
  name        = "obelisk-api-${var.environment}"
  port        = 8443
  protocol    = "HTTPS"
  vpc_id      = module.vpc.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

# WAF
resource "aws_wafv2_web_acl" "obelisk" {
  name        = "obelisk-${var.environment}"
  description = "OBELISK WAF rules"
  scope       = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "RateLimit"
    priority = 1
    action   { block {} }
    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "obelisk-${var.environment}"
    sampled_requests_enabled   = true
  }
}

# Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "alb_dns" {
  description = "Application Load Balancer DNS"
  value       = aws_lb.obelisk.dns_name
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.obelisk.address
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.obelisk.primary_endpoint_address
}

output "ecr_repository_url" {
  description = "ECR Repository URL"
  value       = aws_ecr_repository.obelisk.repository_url
}

output "kms_key_arn" {
  description = "OBELISK KMS Key ARN"
  value       = aws_kms_key.obelisk.arn
}
