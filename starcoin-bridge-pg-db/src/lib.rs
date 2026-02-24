// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use diesel::migration::{Migration, MigrationSource, MigrationVersion};
use diesel::pg::Pg;
use diesel::ConnectionError;
use diesel_async::async_connection_wrapper::AsyncConnectionWrapper;
use diesel_async::pooled_connection::ManagerConfig;
use diesel_async::{
    pooled_connection::{
        bb8::{Pool, PooledConnection},
        AsyncDieselConnectionManager,
    },
    AsyncPgConnection, RunQueryDsl,
};
use futures::FutureExt;
use tracing::info;
use url::Url;

use tls::{build_tls_config, establish_tls_connection};

mod model;
pub mod tls;

pub use starcoin_bridge_field_count::FieldCount;
pub use starcoin_bridge_sql_macro::sql;
pub use tls::{
    build_tls_config as build_pg_tls_config,
    establish_tls_connection as establish_pg_tls_connection,
};

pub mod query;
pub mod schema;
pub mod temp;

use diesel_migrations::{embed_migrations, EmbeddedMigrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(clap::Args, Debug, Clone)]
pub struct DbArgs {
    // Number of connections to keep in the pool.
    #[arg(long, default_value_t = Self::default().db_connection_pool_size)]
    pub db_connection_pool_size: u32,

    // Time spent waiting for a connection from the pool to become available, in milliseconds.
    #[arg(long, default_value_t = Self::default().db_connection_timeout_ms)]
    pub db_connection_timeout_ms: u64,

    #[arg(long)]
    // Time spent waiting for statements to complete, in milliseconds.
    pub db_statement_timeout_ms: Option<u64>,

    #[arg(long)]
    // Enable server certificate verification. By default, this is set to false to match the
    // default behavior of libpq.
    pub tls_verify_cert: bool,

    #[arg(long)]
    // Path to a custom CA certificate to use for server certificate verification.
    pub tls_ca_cert_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct Db {
    pool: Pool<AsyncPgConnection>,
    database_url: String,
    tls_config: rustls::ClientConfig,
}

// Wrapper struct over the remote `PooledConnection` type for dealing with the `Store` trait.
pub struct Connection<'a>(PooledConnection<'a, AsyncPgConnection>);

impl DbArgs {
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_millis(self.db_connection_timeout_ms)
    }

    pub fn statement_timeout(&self) -> Option<Duration> {
        self.db_statement_timeout_ms.map(Duration::from_millis)
    }
}

impl Db {
    // Construct a new DB connection pool talking to the database at `database_url` that supports
    // write and reads. Instances of [Db] can be cloned to share access to the same pool.
    pub async fn for_write(database_url: Url, config: DbArgs) -> anyhow::Result<Self> {
        let tls_config = build_tls_config(config.tls_verify_cert, config.tls_ca_cert_path.clone())?;
        let pool = pool(database_url.clone(), config, false).await?;
        Ok(Self {
            pool,
            database_url: database_url.to_string(),
            tls_config,
        })
    }

    // Construct a new DB connection pool talking to the database at `database_url` that defaults
    // to read-only transactions. Instances of [Db] can be cloned to share access to the same
    // pool.
    pub async fn for_read(database_url: Url, config: DbArgs) -> anyhow::Result<Self> {
        let tls_config = build_tls_config(config.tls_verify_cert, config.tls_ca_cert_path.clone())?;
        let pool = pool(database_url.clone(), config, true).await?;
        Ok(Self {
            pool,
            database_url: database_url.to_string(),
            tls_config,
        })
    }

    // Retrieves a connection from the pool. Can fail with a timeout if a connection cannot be
    // established before the [DbArgs::connection_timeout] has elapsed.
    pub async fn connect(&self) -> anyhow::Result<Connection<'_>> {
        Ok(Connection(self.pool.get().await?))
    }

    // Statistics about the connection pool
    pub fn state(&self) -> bb8::State {
        self.pool.state()
    }

    async fn clear_database(&self) -> anyhow::Result<()> {
        info!("Clearing the database...");
        let mut conn = self.connect().await?;
        let drop_all_tables = "
        DO $$ DECLARE
            r RECORD;
        BEGIN
        FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public')
            LOOP
                EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
            END LOOP;
        END $$;";
        diesel::sql_query(drop_all_tables)
            .execute(&mut conn)
            .await?;
        info!("Dropped all tables.");

        let drop_all_procedures = "
        DO $$ DECLARE
            r RECORD;
        BEGIN
            FOR r IN (SELECT proname, oidvectortypes(proargtypes) as argtypes
                      FROM pg_proc INNER JOIN pg_namespace ns ON (pg_proc.pronamespace = ns.oid)
                      WHERE ns.nspname = 'public' AND prokind = 'p')
            LOOP
                EXECUTE 'DROP PROCEDURE IF EXISTS ' || quote_ident(r.proname) || '(' || r.argtypes || ') CASCADE';
            END LOOP;
        END $$;";
        diesel::sql_query(drop_all_procedures)
            .execute(&mut conn)
            .await?;
        info!("Dropped all procedures.");

        let drop_all_functions = "
        DO $$ DECLARE
            r RECORD;
        BEGIN
            FOR r IN (SELECT proname, oidvectortypes(proargtypes) as argtypes
                      FROM pg_proc INNER JOIN pg_namespace ON (pg_proc.pronamespace = pg_namespace.oid)
                      WHERE pg_namespace.nspname = 'public' AND prokind = 'f')
            LOOP
                EXECUTE 'DROP FUNCTION IF EXISTS ' || quote_ident(r.proname) || '(' || r.argtypes || ') CASCADE';
            END LOOP;
        END $$;";
        diesel::sql_query(drop_all_functions)
            .execute(&mut conn)
            .await?;
        info!("Database cleared.");
        Ok(())
    }

    // Run migrations on the database. Use Diesel's `embed_migrations!` macro to generate the
    // `migrations` parameter for your indexer.
    pub async fn run_migrations(
        &self,
        migrations: Option<&'static EmbeddedMigrations>,
    ) -> anyhow::Result<Vec<MigrationVersion<'static>>> {
        use diesel_migrations::MigrationHarness;

        let merged_migrations = merge_migrations(migrations);

        info!("Running migrations ...");
        // Use establish_tls_connection instead of dedicated_connection to ensure TLS is used
        let conn = establish_tls_connection(&self.database_url, self.tls_config.clone())
            .await
            .map_err(|e| anyhow!("Failed to establish TLS connection for migrations: {}", e))?;
        let mut wrapper: AsyncConnectionWrapper<AsyncPgConnection> = conn.into();

        let finished_migrations = tokio::task::spawn_blocking(move || {
            wrapper
                .run_pending_migrations(merged_migrations)
                .map(|versions| versions.iter().map(MigrationVersion::as_owned).collect())
        })
        .await?
        .map_err(|e| anyhow!("Failed to run migrations: {:?}", e))?;

        info!("Migrations complete.");
        Ok(finished_migrations)
    }
}

impl Default for DbArgs {
    fn default() -> Self {
        Self {
            db_connection_pool_size: 100,
            db_connection_timeout_ms: 60_000,
            db_statement_timeout_ms: None,
            tls_verify_cert: false,
            tls_ca_cert_path: None,
        }
    }
}

// Drop all tables, and re-run migrations if supplied.
pub async fn reset_database(
    database_url: Url,
    db_config: DbArgs,
    migrations: Option<&'static EmbeddedMigrations>,
) -> anyhow::Result<()> {
    let db = Db::for_write(database_url, db_config).await?;
    db.clear_database().await?;
    if let Some(migrations) = migrations {
        db.run_migrations(Some(migrations)).await?;
    }

    Ok(())
}

impl<'a> Deref for Connection<'a> {
    type Target = PooledConnection<'a, AsyncPgConnection>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Connection<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

async fn pool(
    database_url: Url,
    args: DbArgs,
    read_only: bool,
) -> anyhow::Result<Pool<AsyncPgConnection>> {
    let statement_timeout = args.statement_timeout();

    // Build TLS configuration once
    let tls_config = build_tls_config(args.tls_verify_cert, args.tls_ca_cert_path.clone())?;

    let mut config = ManagerConfig::default();

    config.custom_setup = Box::new(move |url| {
        let tls_config = tls_config.clone();

        async move {
            let mut conn = establish_tls_connection(url, tls_config).await?;

            if let Some(timeout) = statement_timeout {
                diesel::sql_query(format!("SET statement_timeout = {}", timeout.as_millis()))
                    .execute(&mut conn)
                    .await
                    .map_err(ConnectionError::CouldntSetupConfiguration)?;
            }

            if read_only {
                diesel::sql_query("SET default_transaction_read_only = 'on'")
                    .execute(&mut conn)
                    .await
                    .map_err(ConnectionError::CouldntSetupConfiguration)?;
            }

            Ok(conn)
        }
        .boxed()
    });

    let manager = AsyncDieselConnectionManager::new_with_config(database_url.as_str(), config);

    Ok(Pool::builder()
        .max_size(args.db_connection_pool_size)
        .connection_timeout(args.connection_timeout())
        .build(manager)
        .await?)
}

// Returns new migrations derived from the combination of provided migrations and migrations
// defined in this crate.
pub fn merge_migrations(
    migrations: Option<&'static EmbeddedMigrations>,
) -> impl MigrationSource<Pg> + Send + Sync + 'static {
    struct Migrations(Option<&'static EmbeddedMigrations>);
    impl MigrationSource<Pg> for Migrations {
        fn migrations(&self) -> diesel::migration::Result<Vec<Box<dyn Migration<Pg>>>> {
            let mut migrations = MIGRATIONS.migrations()?;
            if let Some(more_migrations) = self.0 {
                migrations.extend(more_migrations.migrations()?);
            }
            Ok(migrations)
        }
    }

    Migrations(migrations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::prelude::QueryableByName;

    #[derive(Debug, QueryableByName)]
    struct CountResult {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        cnt: i64,
    }

    #[tokio::test] // to set TEST_DATABASE_URL_SSL
    #[ignore] // Requires TEST_DATABASE_URL_SSL environment variable
    async fn test_ssl_require_mode() {
        telemetry_subscribers::init_for_testing();
        let database_url = std::env::var("TEST_DATABASE_URL_SSL")
            .expect("TEST_DATABASE_URL_SSL environment variable must be set");

        let mut url: Url = database_url.parse().expect("Invalid database URL format");

        let mut query_pairs = url.query_pairs_mut();
        query_pairs.clear();
        query_pairs.append_pair("sslmode", "require");
        drop(query_pairs);

        info!("Testing SSL connection with URL: {}", url);

        let db = Db::for_write(url.clone(), DbArgs::default())
            .await
            .expect("Failed to connect to database with sslmode=require");

        let mut conn = db
            .connect()
            .await
            .expect("Failed to get connection from pool");
        let result: CountResult = diesel::sql_query("SELECT 1::BIGINT AS cnt")
            .get_result(&mut conn)
            .await
            .expect("Failed to execute query");

        assert_eq!(result.cnt, 1);
        info!(
            "SSL connection test successful: query returned {}",
            result.cnt
        );

        let ssl_check: Result<CountResult, _> = diesel::sql_query(
            "SELECT COUNT(*)::BIGINT AS cnt FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        )
        .get_result(&mut conn)
        .await;

        if let Ok(ssl_result) = ssl_check {
            if ssl_result.cnt > 0 {
                info!("SSL connection verified: connection is using SSL");
            } else {
                info!("Note: pg_stat_ssl returned 0 rows (may not be available in this PostgreSQL version)");
            }
        } else {
            info!("Note: Could not query pg_stat_ssl (may not be available in this PostgreSQL version)");
        }
    }
}
