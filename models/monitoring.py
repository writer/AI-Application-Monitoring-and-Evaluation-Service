import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship

db = SQLAlchemy()

class AIApplication(db.Model):
    """Model for storing AI application configurations."""
    
    __tablename__ = 'ai_applications'
    
    id = Column(Integer, primary_key=True)
    app_id = Column(String(100), nullable=False)  # User-provided app ID
    org_id = Column(String(100), nullable=False)  # Organization ID
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    customer_id = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Configuration
    guardrails_config = Column(JSON, nullable=True)  # Custom guardrails configuration
    default_policy = Column(String(100), default="default", nullable=False)
    
    # Relationships
    requests = relationship("AIRequest", back_populates="application")
    
    # Add a unique constraint for app_id and org_id combination
    __table_args__ = (db.UniqueConstraint('app_id', 'org_id', name='unique_app_id_org_id'),)
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "app_id": self.app_id,
            "org_id": self.org_id,
            "name": self.name,
            "description": self.description,
            "customer_id": self.customer_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "active": self.active,
            "default_policy": self.default_policy,
            "guardrails_config": self.guardrails_config
        }

class AIRequest(db.Model):
    """Model for storing AI request data."""
    
    __tablename__ = 'ai_requests'
    
    id = Column(Integer, primary_key=True)
    request_id = Column(String(36), unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    user_id = Column(String(100), nullable=True)
    original_prompt = Column(Text, nullable=False)
    masked_prompt = Column(Text, nullable=True)
    session_id = Column(String(36), nullable=True)
    policy_applied = Column(String(100), nullable=True)
    app_id = Column(String(100), nullable=True)
    org_id = Column(String(100), nullable=True)
    
    # Relationships
    detections = relationship("SensitiveDataDetection", back_populates="request", cascade="all, delete-orphan")
    vulnerabilities = relationship("VulnerabilityDetection", back_populates="request", cascade="all, delete-orphan")
    response = relationship("AIResponse", back_populates="request", uselist=False, cascade="all, delete-orphan")
    application = relationship(
        "AIApplication", 
        primaryjoin="and_(AIRequest.app_id==AIApplication.app_id, AIRequest.org_id==AIApplication.org_id)",
        back_populates="requests",
        foreign_keys=[app_id, org_id]
    )
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "original_prompt": self.original_prompt,
            "masked_prompt": self.masked_prompt,
            "session_id": self.session_id,
            "policy_applied": self.policy_applied,
            "app_id": self.app_id,
            "org_id": self.org_id,
            "detections": [detection.to_dict() for detection in self.detections],
            "vulnerabilities": [vulnerability.to_dict() for vulnerability in self.vulnerabilities],
            "response": self.response.to_dict() if self.response else None
        }


class SensitiveDataDetection(db.Model):
    """Model for storing sensitive data detection results."""
    
    __tablename__ = 'sensitive_data_detections'
    
    id = Column(Integer, primary_key=True)
    request_id = Column(Integer, ForeignKey('ai_requests.id'), nullable=False)
    data_type = Column(String(50), nullable=False)  # pii, phi, pci, ip
    description = Column(String(255), nullable=False)
    action_taken = Column(String(50), nullable=False)  # mask, block, log
    confidence = Column(Float, nullable=True)
    
    # Relationships
    request = relationship("AIRequest", back_populates="detections")
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "data_type": self.data_type,
            "description": self.description,
            "action_taken": self.action_taken,
            "confidence": self.confidence
        }


class VulnerabilityDetection(db.Model):
    """Model for storing vulnerability detection results."""
    
    __tablename__ = 'vulnerability_detections'
    
    id = Column(Integer, primary_key=True)
    request_id = Column(Integer, ForeignKey('ai_requests.id'), nullable=False)
    vulnerability_id = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=True)
    
    # Relationships
    request = relationship("AIRequest", back_populates="vulnerabilities")
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence
        }


class AIResponse(db.Model):
    """Model for storing AI response data."""
    
    __tablename__ = 'ai_responses'
    
    id = Column(Integer, primary_key=True)
    request_id = Column(Integer, ForeignKey('ai_requests.id'), nullable=False, unique=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    masked_response = Column(Text, nullable=True)
    rehydrated_response = Column(Text, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    
    # Relationships
    request = relationship("AIRequest", back_populates="response")
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "masked_response": self.masked_response,
            "rehydrated_response": self.rehydrated_response,
            "completion_tokens": self.completion_tokens,
            "prompt_tokens": self.prompt_tokens,
            "total_tokens": self.total_tokens
        }


class MonitoringMetrics(db.Model):
    """Model for storing monitoring metrics."""
    
    __tablename__ = 'monitoring_metrics'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Float, nullable=False)
    dimensions = Column(JSON, nullable=True)
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "dimensions": self.dimensions
        }


class CustomGuardrailRule(db.Model):
    """Model for storing custom guardrail rules."""
    
    __tablename__ = 'custom_guardrail_rules'
    
    id = Column(Integer, primary_key=True)
    rule_id = Column(String(36), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    customer_id = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    rule_type = Column(String(50), nullable=False)  # regex, semantic, llm
    pattern = Column(Text, nullable=True)  # For regex rules
    prompt_template = Column(Text, nullable=True)  # For LLM-based rules
    data_type = Column(String(50), nullable=False)  # pii, phi, pci, ip, custom
    default_action = Column(String(50), default="mask", nullable=False)  # mask, block, log
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "customer_id": self.customer_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "rule_type": self.rule_type,
            "pattern": self.pattern,
            "prompt_template": self.prompt_template,
            "data_type": self.data_type,
            "default_action": self.default_action
        } 