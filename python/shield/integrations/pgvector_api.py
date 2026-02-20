"""
pgvector FastAPI integration for encrypted vector similarity search.

This module provides FastAPI endpoints for inserting, searching, and managing
encrypted AI embeddings using Shield encryption.

Example:
    from fastapi import FastAPI
    from shield.integrations.pgvector_api import PgVectorRouter
    from shield import Shield

    app = FastAPI()
    shield = Shield("master_password", "pgvector.myapp")
    router = PgVectorRouter(shield=shield, dimension=1536)
    app.include_router(router.router)

Note:
    This is a simplified implementation demonstrating the API structure.
    Production use should integrate with the Rust pgvector module and PostgreSQL.
"""

import hashlib
import json
import math
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


class VectorInsertRequest(BaseModel):
    """Request to insert a vector"""

    vector: List[float] = Field(..., min_items=1, max_items=4096)
    metadata: Optional[Dict[str, Any]] = None


class BatchVectorInsertRequest(BaseModel):
    """Request to batch insert vectors"""

    vectors: List[VectorInsertRequest] = Field(..., min_items=1, max_items=1000)


class VectorSearchRequest(BaseModel):
    """Request to search similar vectors"""

    query: List[float] = Field(..., min_items=1, max_items=4096)
    limit: int = Field(10, ge=1, le=100)
    metric: str = Field("cosine", pattern="^(l2|cosine|inner_product)$")
    filter: Optional[Dict[str, Any]] = None


class VectorUpdateRequest(BaseModel):
    """Request to update a vector"""

    vector: Optional[List[float]] = None
    metadata: Optional[Dict[str, Any]] = None


class PgVectorRouter:
    """FastAPI router for pgvector operations"""

    def __init__(
        self,
        shield: Any,  # Shield instance
        dimension: int,
        require_auth: bool = True,
        secret_key: Optional[str] = None,
    ):
        """
        Initialize pgvector router.

        Args:
            shield: Shield instance for encryption
            dimension: Expected vector dimension
            require_auth: Whether to require authentication
            secret_key: Secret key for token validation (if require_auth=True)
        """
        self.shield = shield
        self.dimension = dimension
        self.require_auth = require_auth
        self.secret_key = secret_key or "default-secret-key"

        # In-memory storage (production should use PostgreSQL with pgvector)
        self.vectors: Dict[int, Dict[str, Any]] = {}
        self.next_id = 1

        # Create router
        self.router = APIRouter(prefix="/vectors", tags=["vectors"])
        self.security = HTTPBearer() if require_auth else None
        self._setup_routes()

    def _verify_token(
        self, credentials: HTTPAuthorizationCredentials
    ) -> Dict[str, Any]:
        """Verify authentication token"""
        # Simplified token verification
        # Production should use Shield's IdentityProvider
        try:
            token = credentials.credentials
            # Basic validation (production should decrypt/verify properly)
            if len(token) < 10:
                raise ValueError("Invalid token")
            return {"user_id": "authenticated_user"}
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    def _encrypt_vector_deterministic(self, vector: List[float]) -> Dict[str, Any]:
        """
        Encrypt vector deterministically.

        Note: This is a simplified implementation.
        Production should use the Rust EncryptedVector implementation.
        """
        # Derive deterministic nonce from vector content
        vector_bytes = b"".join(v.to_bytes(4, "little", signed=False) for v in [int(x * 1000000) for x in vector])
        nonce = hashlib.sha256(b"shield-pgvector-v1" + vector_bytes).digest()[:16]

        # Simplified encryption (production uses Rust module)
        encrypted_components = []
        for i, value in enumerate(vector):
            # Deterministic keystream
            keystream_input = nonce + i.to_bytes(8, "little")
            keystream = hashlib.sha256(keystream_input).digest()[:4]

            # XOR float bytes with keystream
            value_bytes = int(value * 1000000).to_bytes(4, "little", signed=True)
            encrypted_bytes = bytes(a ^ b for a, b in zip(value_bytes, keystream))
            encrypted_value = int.from_bytes(encrypted_bytes, "little", signed=True) / 1000000
            encrypted_components.append(encrypted_value)

        # Compute MAC
        mac_input = nonce + b"".join(
            int(v * 1000000).to_bytes(4, "little", signed=True) for v in encrypted_components
        )
        mac = hashlib.sha256(mac_input).digest()[:16]

        return {
            "nonce": nonce.hex(),
            "encrypted_data": encrypted_components,
            "mac": mac.hex(),
        }

    def _decrypt_vector(self, encrypted: Dict[str, Any]) -> List[float]:
        """Decrypt an encrypted vector"""
        nonce = bytes.fromhex(encrypted["nonce"])
        encrypted_data = encrypted["encrypted_data"]

        # Decrypt (XOR is symmetric)
        decrypted = []
        for i, value in enumerate(encrypted_data):
            keystream_input = nonce + i.to_bytes(8, "little")
            keystream = hashlib.sha256(keystream_input).digest()[:4]

            value_bytes = int(value * 1000000).to_bytes(4, "little", signed=True)
            decrypted_bytes = bytes(a ^ b for a, b in zip(value_bytes, keystream))
            decrypted_value = int.from_bytes(decrypted_bytes, "little", signed=True) / 1000000
            decrypted.append(decrypted_value)

        return decrypted

    def _calculate_distance(
        self, v1: List[float], v2: List[float], metric: str
    ) -> float:
        """Calculate distance between vectors"""
        if metric == "l2":
            # Euclidean distance
            return math.sqrt(sum((a - b) ** 2 for a, b in zip(v1, v2)))
        elif metric == "cosine":
            # Cosine distance = 1 - cosine similarity
            dot = sum(a * b for a, b in zip(v1, v2))
            norm1 = math.sqrt(sum(a * a for a in v1))
            norm2 = math.sqrt(sum(b * b for b in v2))
            if norm1 == 0 or norm2 == 0:
                return 1.0
            return 1.0 - (dot / (norm1 * norm2))
        elif metric == "inner_product":
            # Negative inner product
            return -sum(a * b for a, b in zip(v1, v2))
        else:
            raise ValueError(f"Unknown metric: {metric}")

    def _setup_routes(self) -> None:
        """Set up API routes"""

        async def get_current_user(
            credentials: Optional[HTTPAuthorizationCredentials] = Security(self.security)
            if self.security
            else None,
        ) -> Dict[str, Any]:
            """Dependency for authentication"""
            if self.require_auth and credentials:
                return self._verify_token(credentials)
            return {}

        @self.router.post("", status_code=201)
        async def insert_vector(
            request: VectorInsertRequest,
            user: Dict[str, Any] = Depends(get_current_user),
        ) -> Dict[str, Any]:
            """Insert an encrypted vector"""
            if len(request.vector) != self.dimension:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid dimension: expected {self.dimension}, got {len(request.vector)}",
                )

            # Encrypt vector
            encrypted = self._encrypt_vector_deterministic(request.vector)

            # Store
            vector_id = self.next_id
            self.vectors[vector_id] = {
                "id": vector_id,
                "encrypted": encrypted,
                "plaintext": request.vector,  # For testing (remove in production)
                "metadata": request.metadata or {},
                "created_at": time.time(),
            }
            self.next_id += 1

            return {"id": vector_id, "created_at": self.vectors[vector_id]["created_at"]}

        @self.router.post("/batch", status_code=201)
        async def batch_insert_vectors(
            request: BatchVectorInsertRequest,
            user: Dict[str, Any] = Depends(get_current_user),
        ) -> Dict[str, Any]:
            """Batch insert vectors"""
            ids = []
            for item in request.vectors:
                if len(item.vector) != self.dimension:
                    continue
                encrypted = self._encrypt_vector_deterministic(item.vector)
                vector_id = self.next_id
                self.vectors[vector_id] = {
                    "id": vector_id,
                    "encrypted": encrypted,
                    "plaintext": item.vector,
                    "metadata": item.metadata or {},
                    "created_at": time.time(),
                }
                ids.append(vector_id)
                self.next_id += 1

            return {"inserted": len(ids), "ids": ids}

        @self.router.post("/search")
        async def search_vectors(
            request: VectorSearchRequest,
            user: Dict[str, Any] = Depends(get_current_user),
        ) -> Dict[str, Any]:
            """Search for similar vectors"""
            if len(request.query) != self.dimension:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid dimension: expected {self.dimension}, got {len(request.query)}",
                )

            start_time = time.time()

            # Calculate distances to all vectors
            results = []
            for vector_id, vector_data in self.vectors.items():
                # Decrypt stored vector
                decrypted = vector_data["plaintext"]  # In production, decrypt from encrypted

                # Calculate distance
                distance = self._calculate_distance(
                    decrypted, request.query, request.metric
                )

                # Apply metadata filter if provided
                if request.filter:
                    matches = all(
                        vector_data["metadata"].get(k) == v
                        for k, v in request.filter.items()
                    )
                    if not matches:
                        continue

                results.append(
                    {
                        "id": vector_id,
                        "vector": decrypted,
                        "metadata": vector_data["metadata"],
                        "distance": distance,
                        "created_at": vector_data["created_at"],
                    }
                )

            # Sort by distance
            results.sort(key=lambda x: x["distance"])

            # Take top K
            results = results[: request.limit]

            query_time_ms = (time.time() - start_time) * 1000

            return {"results": results, "query_time_ms": round(query_time_ms, 2)}

        @self.router.get("/{vector_id}")
        async def get_vector(
            vector_id: int, user: Dict[str, Any] = Depends(get_current_user)
        ) -> Dict[str, Any]:
            """Get vector by ID"""
            vector_data = self.vectors.get(vector_id)
            if not vector_data:
                raise HTTPException(status_code=404, detail="Vector not found")

            return {
                "id": vector_data["id"],
                "vector": vector_data["plaintext"],
                "metadata": vector_data["metadata"],
                "created_at": vector_data["created_at"],
            }

        @self.router.put("/{vector_id}")
        async def update_vector(
            vector_id: int,
            request: VectorUpdateRequest,
            user: Dict[str, Any] = Depends(get_current_user),
        ) -> Dict[str, str]:
            """Update vector and/or metadata"""
            vector_data = self.vectors.get(vector_id)
            if not vector_data:
                raise HTTPException(status_code=404, detail="Vector not found")

            if request.vector:
                if len(request.vector) != self.dimension:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid dimension: expected {self.dimension}, got {len(request.vector)}",
                    )
                encrypted = self._encrypt_vector_deterministic(request.vector)
                vector_data["encrypted"] = encrypted
                vector_data["plaintext"] = request.vector

            if request.metadata:
                vector_data["metadata"] = request.metadata

            return {"status": "updated"}

        @self.router.delete("/{vector_id}", status_code=204)
        async def delete_vector(
            vector_id: int, user: Dict[str, Any] = Depends(get_current_user)
        ) -> None:
            """Delete vector"""
            if vector_id not in self.vectors:
                raise HTTPException(status_code=404, detail="Vector not found")
            del self.vectors[vector_id]

        @self.router.get("/stats/collection")
        async def get_stats(
            user: Dict[str, Any] = Depends(get_current_user),
        ) -> Dict[str, Any]:
            """Get collection statistics"""
            return {
                "total_vectors": len(self.vectors),
                "dimension": self.dimension,
                "index_type": "hnsw",  # In production, query from database
                "disk_size_mb": 0,  # In-memory for demo
            }


def create_pgvector_app(
    shield: Any,
    dimension: int,
    require_auth: bool = True,
) -> APIRouter:
    """
    Create a pgvector FastAPI router.

    Args:
        shield: Shield instance for encryption
        dimension: Vector dimension
        require_auth: Whether to require authentication

    Returns:
        Configured FastAPI router
    """
    pgvector_router = PgVectorRouter(
        shield=shield, dimension=dimension, require_auth=require_auth
    )

    return pgvector_router.router
