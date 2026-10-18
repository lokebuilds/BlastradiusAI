"""
BlastradiusAI - Topology Seeder
Generates a realistic enterprise zero-trust cloud infrastructure graph
featuring multi-hop service calls, toxic IAM privilege escalation pathways,
and sensitive crown-jewel assets (PII, KMS keys, S3 vaults).
"""

import logging
from tools import db_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_graph")


def seed_database():
    """Seeds the zero-trust cloud infrastructure topology into FalkorDB and embedded engine."""
    logger.info("Initializing zero-trust cloud infrastructure topology...")

    # Clear existing state
    db_client.embedded_engine.nodes.clear()
    db_client.embedded_engine.edges.clear()

    # Clear FalkorDB if connected
    if not db_client.is_embedded and db_client.graph:
        try:
            db_client.graph.query("MATCH (n) DETACH DELETE n")
            logger.info("Cleared existing FalkorDB graph nodes and relationships.")
        except Exception as e:
            logger.warning(f"Failed to clear FalkorDB graph: {e}")

    # 1. Define Nodes adhering to T-CoT schema (Gateway, Service, Host, Role, Database, Storage)
    nodes = [
        # Ingress / Network Boundary
        {
            "id": "igw-main",
            "labels": ["Gateway", "InternetGateway", "NetworkBoundary"],
            "props": {
                "name": "igw-main",
                "tier": "edge",
                "ip": "0.0.0.0/0",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["PUBLIC_INGRESS", "NETWORK"],
                "description": "AWS Internet Gateway for Production VPC",
                "status": "HEALTHY"
            }
        },
        {
            "id": "alb-external",
            "labels": ["Gateway", "ApplicationLoadBalancer", "Ingress"],
            "props": {
                "name": "alb-external-prod",
                "tier": "dmz",
                "ip": "54.210.88.14",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["INGRESS", "SSL_TERMINATION"],
                "description": "Public HTTPS Application Load Balancer",
                "status": "HEALTHY"
            }
        },
        # Public-Facing Workloads
        {
            "id": "auth-service",
            "labels": ["Service", "Host", "Compute"],
            "props": {
                "name": "auth-service",
                "tier": "tier-1-public",
                "ip": "10.0.1.44",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["OAUTH", "PUBLIC_EXPOSED", "VULNERABLE_CVE_2024"],
                "description": "OAuth2 / SAML authentication microservice pod",
                "status": "HEALTHY"
            }
        },
        {
            "id": "marketing-portal",
            "labels": ["Service", "Host", "Compute"],
            "props": {
                "name": "marketing-portal",
                "tier": "tier-1-public",
                "ip": "10.0.1.89",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["PUBLIC_WEB", "STATIC_ASSETS"],
                "description": "Marketing and public product catalog frontend",
                "status": "HEALTHY"
            }
        },
        # Internal Tier Workloads
        {
            "id": "order-service",
            "labels": ["Service", "Host", "Compute"],
            "props": {
                "name": "order-service",
                "tier": "tier-2-internal",
                "ip": "10.0.2.105",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["INTERNAL_API", "COMMERCE"],
                "description": "Order management service processing customer carts",
                "status": "HEALTHY"
            }
        },
        {
            "id": "payment-service",
            "labels": ["Service", "Host", "Compute"],
            "props": {
                "name": "payment-service",
                "tier": "tier-3-isolated",
                "ip": "10.0.3.12",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["FINTECH", "PCI_SCOPE"],
                "description": "Payment authorization gateway processing card transactions",
                "status": "HEALTHY"
            }
        },
        {
            "id": "notification-worker",
            "labels": ["Service", "Worker"],
            "props": {
                "name": "notification-worker",
                "tier": "tier-2-internal",
                "ip": "10.0.2.220",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["ASYNC_WORKER", "EMAIL_SMS"],
                "description": "Background worker sending customer delivery alerts",
                "status": "HEALTHY"
            }
        },
        # IAM Identities & Roles
        {
            "id": "Role_AuthService",
            "labels": ["Role", "Identity"],
            "props": {
                "name": "Role_AuthService",
                "tier": "iam-identity",
                "role_arn": "arn:aws:iam::112233445566:role/auth-service-profile",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["IAM", "TOKEN_EXCHANGE"],
                "description": "IAM execution role bound to auth-service container",
                "status": "HEALTHY"
            }
        },
        {
            "id": "Role_PaymentProcessor",
            "labels": ["Role", "Identity"],
            "props": {
                "name": "Role_PaymentProcessor",
                "tier": "iam-identity",
                "role_arn": "arn:aws:iam::112233445566:role/high-privilege-payment-vault",
                "critical": True,
                "has_pii": False,
                "elevated": True,
                "tags": ["IAM", "PRIVILEGED_ROLE", "KMS_DECRYPT"],
                "description": "High-privilege role possessing S3 & KMS decryption grants",
                "status": "HEALTHY"
            }
        },
        {
            "id": "Role_Marketing",
            "labels": ["Role", "Identity"],
            "props": {
                "name": "Role_Marketing",
                "tier": "iam-identity",
                "role_arn": "arn:aws:iam::112233445566:role/marketing-readonly",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["IAM", "LOW_PRIVILEGE"],
                "description": "Read-only marketing analytics role",
                "status": "HEALTHY"
            }
        },
        # Crown Jewel Sensitive Assets (PII, KMS, Databases, Storage)
        {
            "id": "rds-customer-pii",
            "labels": ["Database", "DataStore", "CrownJewel"],
            "props": {
                "name": "rds-customer-pii",
                "tier": "tier-4-data",
                "ip": "10.0.4.50",
                "critical": True,
                "has_pii": True,
                "elevated": False,
                "tags": ["PII", "CRITICAL", "PCI_DSS", "CUSTOMER_DATA"],
                "description": "PostgreSQL Primary Cluster containing credit cards & SSNs",
                "status": "HEALTHY"
            }
        },
        {
            "id": "s3-customer-vault",
            "labels": ["Storage", "S3Bucket", "CrownJewel"],
            "props": {
                "name": "s3-customer-vault-prod",
                "tier": "tier-4-data",
                "critical": True,
                "has_pii": True,
                "elevated": False,
                "tags": ["PII", "CRITICAL", "CONFIDENTIAL", "ENCRYPTED_DOCUMENTS"],
                "description": "S3 Data Vault containing KYC identity verification docs",
                "status": "HEALTHY"
            }
        },
        {
            "id": "kms-payment-keys",
            "labels": ["Storage", "CryptographicKey", "CrownJewel"],
            "props": {
                "name": "kms-payment-keys",
                "tier": "security-core",
                "critical": True,
                "has_pii": False,
                "elevated": True,
                "tags": ["SECURITY", "CRITICAL", "HSM_BACKED"],
                "description": "AWS KMS Customer Managed Key used to decrypt card vault",
                "status": "HEALTHY"
            }
        },
        {
            "id": "rds-analytics-replica",
            "labels": ["Database", "DataStore"],
            "props": {
                "name": "rds-analytics-replica",
                "tier": "tier-4-data",
                "ip": "10.0.4.99",
                "critical": False,
                "has_pii": False,
                "elevated": False,
                "tags": ["ANALYTICS", "NON_SENSITIVE"],
                "description": "Read replica with anonymized web traffic logs",
                "status": "HEALTHY"
            }
        },
        # Episodic Historical Incident Memory
        {
            "id": "INC-2026-0412",
            "labels": ["Incident", "AuditRecord"],
            "props": {
                "name": "INC-2026-0412",
                "timestamp": "2026-04-12T08:15:00Z",
                "symptom": "Anomalous ingress probe targeting CVE-2024-38077",
                "action": "BLOCKED_BY_PERIMETER",
                "cve": "CVE-2024-38077-Probe",
                "reason": "Host header injection blocked; ingress rate-limited",
                "status": "RESOLVED"
            }
        }
    ]

    for n in nodes:
        db_client.embedded_engine.add_node(n["id"], n["labels"], n["props"])

    # 2. Define Relationships / Edges
    edges = [
        # Public Ingress routing
        ("igw-main", "alb-external", "ROUTES_TO", {"protocol": "HTTPS", "port": 443}),
        ("alb-external", "auth-service", "FORWARDS_TO", {"path": "/auth/*", "port": 8080}),
        ("alb-external", "marketing-portal", "FORWARDS_TO", {"path": "/app/*", "port": 3000}),

        # Microservice lateral API network calls
        ("auth-service", "order-service", "CALLS_API", {"protocol": "gRPC", "port": 9090, "encrypted": True}),
        ("order-service", "payment-service", "CALLS_API", {"protocol": "mTLS", "port": 8443, "encrypted": True}),
        ("payment-service", "rds-customer-pii", "QUERIES", {"protocol": "Postgres", "port": 5432, "auth": "IAM_AUTH"}),

        # Toxic Identity Privilege Escalation (STS AssumeRole path)
        ("auth-service", "Role_AuthService", "ASSUMES_ROLE", {"mechanism": "InstanceProfile"}),
        ("Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME", {"policy": "sts:AssumeRole", "toxic_choke_point": True}),
        ("Role_PaymentProcessor", "s3-customer-vault", "READS_DATA", {"permission": "s3:GetObject"}),
        ("Role_PaymentProcessor", "kms-payment-keys", "DECRYPTS_WITH", {"permission": "kms:Decrypt"}),

        # Healthy Workload Branch
        ("marketing-portal", "Role_Marketing", "ASSUMES_ROLE", {"mechanism": "ECS_TaskRole"}),
        ("marketing-portal", "rds-analytics-replica", "QUERIES", {"protocol": "Postgres", "port": 5432}),
        ("notification-worker", "order-service", "LISTENS_TO", {"protocol": "Kafka/Event", "port": 9092}),

        # Historical episodic memory edge
        ("INC-2026-0412", "auth-service", "TARGETED", {"timestamp": "2026-04-12T08:15:00Z"})
    ]

    for src, tgt, rel, props in edges:
        db_client.embedded_engine.add_edge(src, tgt, rel, props)

    # 3. Synchronize with FalkorDB if available
    if not db_client.is_embedded and db_client.graph:
        try:
            for n in nodes:
                lbl = ":".join(n["labels"])
                props_str = ", ".join([f"{k}: '{v}'" if isinstance(v, str) else f"{k}: {v}" for k, v in n["props"].items() if not isinstance(v, list)])
                db_client.graph.query(f"CREATE (:{lbl} {{{props_str}}})")

            for src, tgt, rel, props in edges:
                db_client.graph.query(
                    f"MATCH (a {{id: '{src}'}}), (b {{id: '{tgt}'}}) "
                    f"CREATE (a)-[:{rel} {{status: 'ACTIVE'}}]->(b)"
                )
            logger.info("Successfully synchronized full graph topology with FalkorDB.")
        except Exception as e:
            logger.warning(f"FalkorDB sync error: {e}. Embedded engine is fully primed.")

    logger.info(
        f"Graph primed successfully: {len(db_client.embedded_engine.nodes)} nodes, "
        f"{len(db_client.embedded_engine.edges)} directional relationships."
    )
    return {
        "status": "success",
        "nodes_count": len(db_client.embedded_engine.nodes),
        "edges_count": len(db_client.embedded_engine.edges),
        "engine": "FalkorDB" if not db_client.is_embedded else "Embedded-Topological-Cypher-Engine"
    }


if __name__ == "__main__":
    result = seed_database()
    print("Seed result:", result)
