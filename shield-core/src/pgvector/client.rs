//! pgvector client for PostgreSQL operations
//!
//! NOTE: This is a simplified implementation demonstrating the integration pattern.
//! Production use requires tokio-postgres with actual database connections.

use super::config::{DistanceMetric, PgVectorConfig};
use super::error::{PgVectorError, Result};
use super::vector::EncryptedVector;
use crate::Shield;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vector record with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorRecord {
    /// Record ID
    pub id: i64,
    /// Decrypted vector
    pub vector: Vec<f32>,
    /// Metadata (arbitrary JSON)
    pub metadata: serde_json::Value,
    /// Distance from query (for search results)
    pub distance: Option<f64>,
}

/// Mock pgvector client for demonstration
///
/// In production, this would use tokio-postgres with connection pooling
pub struct PgVectorClient {
    config: PgVectorConfig,
    shield: Shield,
    // Mock storage (in production, this would be PostgreSQL)
    storage: HashMap<i64, (EncryptedVector, serde_json::Value)>,
    next_id: i64,
}

impl PgVectorClient {
    /// Create a new pgvector client
    pub fn new(config: PgVectorConfig, shield: Shield) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            shield,
            storage: HashMap::new(),
            next_id: 1,
        })
    }

    /// Insert a vector with metadata
    pub fn insert(
        &mut self,
        vector: &[f32],
        metadata: serde_json::Value,
    ) -> Result<i64> {
        // Validate dimension
        if vector.len() != self.config.dimension {
            return Err(PgVectorError::InvalidDimension {
                expected: self.config.dimension,
                actual: vector.len(),
            });
        }

        // Encrypt vector deterministically
        let encrypted = EncryptedVector::encrypt(&self.shield, vector)?;

        // Store (in production: INSERT INTO encrypted_embeddings)
        let id = self.next_id;
        self.storage.insert(id, (encrypted, metadata));
        self.next_id += 1;

        Ok(id)
    }

    /// Search for similar vectors
    pub fn search_similar(
        &self,
        query: &[f32],
        limit: usize,
        metric: DistanceMetric,
    ) -> Result<Vec<VectorRecord>> {
        // Validate dimension
        if query.len() != self.config.dimension {
            return Err(PgVectorError::InvalidDimension {
                expected: self.config.dimension,
                actual: query.len(),
            });
        }

        // Encrypt query vector (for production PostgreSQL queries)
        let _encrypted_query = EncryptedVector::encrypt(&self.shield, query)?;

        // Search in storage (in production: SELECT with ORDER BY distance)
        let mut results: Vec<_> = self.storage
            .iter()
            .map(|(id, (encrypted_vec, metadata))| {
                // Decrypt stored vector
                let vector = encrypted_vec.decrypt(&self.shield).ok()?;

                // Calculate distance
                let distance = Self::calculate_distance(&vector, query, metric);

                Some(VectorRecord {
                    id: *id,
                    vector,
                    metadata: metadata.clone(),
                    distance: Some(distance),
                })
            })
            .filter_map(|x| x)
            .collect();

        // Sort by distance
        results.sort_by(|a, b| {
            a.distance.partial_cmp(&b.distance).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top K
        results.truncate(limit);

        Ok(results)
    }

    /// Get vector by ID
    pub fn get(&self, id: i64) -> Result<Option<VectorRecord>> {
        match self.storage.get(&id) {
            Some((encrypted, metadata)) => {
                let vector = encrypted.decrypt(&self.shield)?;
                Ok(Some(VectorRecord {
                    id,
                    vector,
                    metadata: metadata.clone(),
                    distance: None,
                }))
            }
            None => Ok(None),
        }
    }

    /// Delete vector by ID
    pub fn delete(&mut self, id: i64) -> Result<bool> {
        Ok(self.storage.remove(&id).is_some())
    }

    /// Update vector
    pub fn update(
        &mut self,
        id: i64,
        vector: &[f32],
        metadata: serde_json::Value,
    ) -> Result<()> {
        if !self.storage.contains_key(&id) {
            return Err(PgVectorError::VectorNotFound);
        }

        if vector.len() != self.config.dimension {
            return Err(PgVectorError::InvalidDimension {
                expected: self.config.dimension,
                actual: vector.len(),
            });
        }

        let encrypted = EncryptedVector::encrypt(&self.shield, vector)?;
        self.storage.insert(id, (encrypted, metadata));

        Ok(())
    }

    /// Get collection statistics
    pub fn stats(&self) -> CollectionStats {
        CollectionStats {
            total_vectors: self.storage.len() as i64,
            dimension: self.config.dimension,
        }
    }

    /// Calculate distance between two vectors
    fn calculate_distance(v1: &[f32], v2: &[f32], metric: DistanceMetric) -> f64 {
        match metric {
            DistanceMetric::L2 => {
                // Euclidean distance
                v1.iter()
                    .zip(v2.iter())
                    .map(|(a, b)| {
                        let diff = a - b;
                        (diff * diff) as f64
                    })
                    .sum::<f64>()
                    .sqrt()
            }
            DistanceMetric::Cosine => {
                // Cosine distance = 1 - cosine similarity
                let dot: f64 = v1.iter().zip(v2.iter()).map(|(a, b)| (a * b) as f64).sum();
                let norm1: f64 = v1.iter().map(|x| (x * x) as f64).sum::<f64>().sqrt();
                let norm2: f64 = v2.iter().map(|x| (x * x) as f64).sum::<f64>().sqrt();

                if norm1 == 0.0 || norm2 == 0.0 {
                    1.0
                } else {
                    1.0 - (dot / (norm1 * norm2))
                }
            }
            DistanceMetric::InnerProduct => {
                // Negative inner product
                -(v1.iter().zip(v2.iter()).map(|(a, b)| (a * b) as f64).sum::<f64>())
            }
        }
    }
}

/// Collection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionStats {
    /// Total number of vectors
    pub total_vectors: i64,
    /// Vector dimension
    pub dimension: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_client() -> PgVectorClient {
        let config = PgVectorConfig::new("postgresql://localhost/test", 3);
        let shield = Shield::new("test_password", "pgvector.test");
        PgVectorClient::new(config, shield).unwrap()
    }

    #[test]
    fn test_insert_and_retrieve() {
        let mut client = create_test_client();
        let vector = vec![1.0, 2.0, 3.0];
        let metadata = serde_json::json!({"text": "test"});

        let id = client.insert(&vector, metadata.clone()).unwrap();
        let record = client.get(id).unwrap().unwrap();

        assert_eq!(record.id, id);
        assert_eq!(record.vector, vector);
        assert_eq!(record.metadata, metadata);
    }

    #[test]
    fn test_similarity_search() {
        let mut client = create_test_client();

        // Insert vectors
        client.insert(&vec![1.0, 0.0, 0.0], serde_json::json!({"id": "v1"})).unwrap();
        client.insert(&vec![0.9, 0.1, 0.0], serde_json::json!({"id": "v2"})).unwrap();
        client.insert(&vec![0.0, 1.0, 0.0], serde_json::json!({"id": "v3"})).unwrap();

        // Search for similar to [1.0, 0.0, 0.0]
        let results = client.search_similar(
            &vec![1.0, 0.0, 0.0],
            2,
            DistanceMetric::L2,
        ).unwrap();

        assert_eq!(results.len(), 2);
        // First result should be exact match
        assert_eq!(results[0].metadata["id"], "v1");
        // Second should be close
        assert_eq!(results[1].metadata["id"], "v2");
    }

    #[test]
    fn test_invalid_dimension() {
        let mut client = create_test_client();
        let wrong_size = vec![1.0, 2.0]; // Expected 3, got 2

        let result = client.insert(&wrong_size, serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn test_delete() {
        let mut client = create_test_client();
        let id = client.insert(&vec![1.0, 2.0, 3.0], serde_json::json!({})).unwrap();

        assert!(client.delete(id).unwrap());
        assert!(client.get(id).unwrap().is_none());
    }

    #[test]
    fn test_update() {
        let mut client = create_test_client();
        let id = client.insert(&vec![1.0, 2.0, 3.0], serde_json::json!({"v": 1})).unwrap();

        client.update(id, &vec![4.0, 5.0, 6.0], serde_json::json!({"v": 2})).unwrap();

        let record = client.get(id).unwrap().unwrap();
        assert_eq!(record.vector, vec![4.0, 5.0, 6.0]);
        assert_eq!(record.metadata["v"], 2);
    }
}
