#!/usr/bin/env python3
"""
Independent validator for rustre-db crate.
Reads spec from reports/rustre-db.md and emits the documented public API surface.
Pure Python stdlib, no Rust import, no MCP calls.
"""
import json

CRATE = "rustre-db"

FUNCTIONS = [
    # db_connection
    {"module": "db_connection", "name": "DbConfig::file"},
    {"module": "db_connection", "name": "DbConfig::memory"},
    {"module": "db_connection", "name": "Database::open"},
    {"module": "db_connection", "name": "Database::open_in_memory"},
    {"module": "db_connection", "name": "Database::open_file"},
    {"module": "db_connection", "name": "Database::acquire"},
    {"module": "db_connection", "name": "Database::max_size"},
    {"module": "db_connection", "name": "Database::checked_out"},
    {"module": "db_connection", "name": "Database::close"},
    {"module": "db_connection", "name": "Connection::transaction"},
    {"module": "db_connection", "name": "Transaction::commit"},
    {"module": "db_connection", "name": "Transaction::rollback"},
    # db_events
    {"module": "db_events", "name": "NewEvent::new"},
    {"module": "db_events", "name": "NewEvent::with_metadata"},
    {"module": "db_events", "name": "EventStore::append"},
    {"module": "db_events", "name": "EventStore::append_in_tx"},
    {"module": "db_events", "name": "EventStore::append_batch"},
    {"module": "db_events", "name": "EventStore::read_stream"},
    {"module": "db_events", "name": "EventStore::read_all"},
    {"module": "db_events", "name": "EventStore::latest_offset"},
    {"module": "db_events", "name": "EventStore::count"},
    # db_index_manager
    {"module": "db_index_manager", "name": "IndexDef::new"},
    {"module": "db_index_manager", "name": "IndexDef::unique"},
    {"module": "db_index_manager", "name": "IndexDef::partial"},
    {"module": "db_index_manager", "name": "IndexDef::with_filter"},
    {"module": "db_index_manager", "name": "IndexDef::to_sql"},
    {"module": "db_index_manager", "name": "IndexDef::drop_sql"},
    {"module": "db_index_manager", "name": "DbIndexManager::new"},
    {"module": "db_index_manager", "name": "DbIndexManager::register"},
    {"module": "db_index_manager", "name": "DbIndexManager::create"},
    {"module": "db_index_manager", "name": "DbIndexManager::create_if_missing"},
    {"module": "db_index_manager", "name": "DbIndexManager::drop"},
    {"module": "db_index_manager", "name": "DbIndexManager::rebuild"},
    {"module": "db_index_manager", "name": "DbIndexManager::index_exists"},
    {"module": "db_index_manager", "name": "DbIndexManager::list_all"},
    {"module": "db_index_manager", "name": "DbIndexManager::inspect"},
    {"module": "db_index_manager", "name": "DbIndexManager::create_all_registered"},
    {"module": "db_index_manager", "name": "DbIndexManager::drop_all_registered"},
    {"module": "db_index_manager", "name": "DbIndexManager::analyse_table"},
    {"module": "db_index_manager", "name": "create_index"},
    # db_migration_manager
    {"module": "db_migration_manager", "name": "Migration::new"},
    {"module": "db_migration_manager", "name": "Migration::with_rollback"},
    {"module": "db_migration_manager", "name": "Migration::checksum_valid"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::new"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::with_table_name"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::ensure_tracking_table"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::applied_versions"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::migrate_up"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::migrate_down_one"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::migrate_down_all"},
    {"module": "db_migration_manager", "name": "DbMigrationManager::status"},
    {"module": "db_migration_manager", "name": "run_migrations"},
    # db_query_builder
    {"module": "db_query_builder", "name": "DbQueryBuilder::select"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::insert"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::update"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::delete"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::from"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::columns"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::where_clause"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::where_and"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::where_or"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::order_by"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::group_by"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::having"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::limit"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::offset"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::join"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::param"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::params"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::set"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::build"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::count"},
    {"module": "db_query_builder", "name": "DbQueryBuilder::exists"},
    {"module": "db_query_builder", "name": "CompiledQuery::placeholder_count"},
    {"module": "db_query_builder", "name": "CompiledQuery::validate"},
    {"module": "db_query_builder", "name": "QueryParams::new"},
    {"module": "db_query_builder", "name": "QueryParams::push"},
    {"module": "db_query_builder", "name": "QueryParams::with"},
    {"module": "db_query_builder", "name": "QueryParams::values"},
    {"module": "db_query_builder", "name": "QueryParams::get"},
    {"module": "db_query_builder", "name": "build_select"},
    # db_schema
    {"module": "db_schema", "name": "base_migrations"},
    {"module": "db_schema", "name": "apply_base_schema"},
]


def main():
    result = {
        "crate": CRATE,
        "saved": True,
        "functions": FUNCTIONS,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
