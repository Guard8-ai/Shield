//! pgvector configuration

use super::error::{PgVectorError, Result};

/// Distance metric for vector similarity search
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistanceMetric {
    /// L2 distance (Euclidean)
    L2,
    /// Cosine distance
    Cosine,
    /// Inner product (negative for nearest neighbor)
    InnerProduct,
}

impl DistanceMetric {
    /// Get SQL operator for this metric
    pub fn operator(&self) -> &'static str {
        match self {
            Self::L2 => "<->",
            Self::Cosine => "<=>",
            Self::InnerProduct => "<#>",
        }
    }

    /// Get pgvector ops class for index creation
    pub fn ops_class(&self) -> &'static str {
        match self {
            Self::L2 => "vector_l2_ops",
            Self::Cosine => "vector_cosine_ops",
            Self::InnerProduct => "vector_ip_ops",
        }
    }
}

/// Index type for pgvector
#[derive(Debug, Clone)]
pub enum IndexType {
    /// HNSW (Hierarchical Navigable Small World)
    HNSW {
        /// Number of connections per layer (default: 16)
        m: u32,
        /// Size of dynamic candidate list (default: 64)
        ef_construction: u32,
    },
    /// IVFFlat (Inverted File with Flat compression)
    IVFFlat {
        /// Number of lists (default: 100)
        lists: u32,
    },
}

impl Default for IndexType {
    fn default() -> Self {
        Self::HNSW {
            m: 16,
            ef_construction: 64,
        }
    }
}

impl IndexType {
    /// Get SQL for index creation
    pub fn create_index_sql(&self, table: &str, column: &str, metric: DistanceMetric) -> String {
        match self {
            Self::HNSW { m, ef_construction } => {
                format!(
                    "CREATE INDEX ON {} USING hnsw ({} {}) WITH (m = {}, ef_construction = {})",
                    table,
                    column,
                    metric.ops_class(),
                    m,
                    ef_construction
                )
            }
            Self::IVFFlat { lists } => {
                format!(
                    "CREATE INDEX ON {} USING ivfflat ({} {}) WITH (lists = {})",
                    table,
                    column,
                    metric.ops_class(),
                    lists
                )
            }
        }
    }
}

/// Configuration for pgvector client
#[derive(Debug, Clone)]
pub struct PgVectorConfig {
    /// PostgreSQL connection string
    pub connection_string: String,
    /// Connection pool size
    pub pool_size: u32,
    /// Table name for encrypted embeddings
    pub table_name: String,
    /// Vector dimension (e.g., 1536 for OpenAI text-embedding-3-small)
    pub dimension: usize,
    /// Index type
    pub index_type: IndexType,
    /// Distance metric
    pub metric: DistanceMetric,
}

impl PgVectorConfig {
    /// Create a new pgvector configuration
    pub fn new(
        connection_string: impl Into<String>,
        dimension: usize,
    ) -> Self {
        Self {
            connection_string: connection_string.into(),
            pool_size: 10,
            table_name: "encrypted_embeddings".to_string(),
            dimension,
            index_type: IndexType::default(),
            metric: DistanceMetric::Cosine,
        }
    }

    /// Set connection pool size
    #[must_use]
    pub fn with_pool_size(mut self, pool_size: u32) -> Self {
        self.pool_size = pool_size;
        self
    }

    /// Set table name
    #[must_use]
    pub fn with_table_name(mut self, table_name: impl Into<String>) -> Self {
        self.table_name = table_name.into();
        self
    }

    /// Set index type
    #[must_use]
    pub fn with_index_type(mut self, index_type: IndexType) -> Self {
        self.index_type = index_type;
        self
    }

    /// Set distance metric
    #[must_use]
    pub fn with_metric(mut self, metric: DistanceMetric) -> Self {
        self.metric = metric;
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.dimension == 0 || self.dimension > 4096 {
            return Err(PgVectorError::InvalidConfig(
                format!("Invalid dimension: {} (must be 1-4096)", self.dimension)
            ));
        }
        if self.pool_size == 0 {
            return Err(PgVectorError::InvalidConfig(
                "Pool size must be > 0".to_string()
            ));
        }
        Ok(())
    }
}
