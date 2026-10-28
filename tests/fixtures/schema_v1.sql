-- Schema created by CryptoGuard 7fe824a (schema version 1), for upgrade tests.
CREATE TABLE address_observations (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	address VARCHAR(42) NOT NULL, 
	block_number BIGINT NOT NULL, 
	block_hash VARCHAR(66) NOT NULL, 
	block_timestamp DATETIME NOT NULL, 
	observation_type VARCHAR(64) NOT NULL, 
	schema_version VARCHAR(64) NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	observed_at DATETIME NOT NULL, 
	payload JSON NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_address_observation_identity UNIQUE (chain_id, address, block_hash, observation_type, data_source)
);
CREATE TABLE approval_events (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	token VARCHAR(42) NOT NULL, 
	owner VARCHAR(42) NOT NULL, 
	spender VARCHAR(42) NOT NULL, 
	value VARCHAR(78) NOT NULL, 
	block_number BIGINT NOT NULL, 
	block_hash VARCHAR(66) NOT NULL, 
	transaction_hash VARCHAR(66) NOT NULL, 
	transaction_index BIGINT NOT NULL, 
	log_index BIGINT NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	ingested_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_approval_event_log UNIQUE (chain_id, block_hash, log_index)
);
CREATE TABLE campaign_expansion_tasks (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	task_id VARCHAR(66) NOT NULL, 
	kind VARCHAR(32) NOT NULL, 
	entity VARCHAR(66) NOT NULL, 
	seed_block BIGINT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	payload JSON NOT NULL, 
	recorded_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_campaign_task UNIQUE (chain_id, data_source, task_id)
);
CREATE TABLE campaign_memberships (
	id INTEGER NOT NULL, 
	run_id INTEGER NOT NULL, 
	cluster_id VARCHAR(32) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	address VARCHAR(42) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_campaign_member UNIQUE (run_id, cluster_id, role, address), 
	FOREIGN KEY(run_id) REFERENCES campaign_runs (id) ON DELETE CASCADE
);
CREATE TABLE campaign_runs (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	cutoff_block BIGINT NOT NULL, 
	algorithm_version VARCHAR(64) NOT NULL, 
	input_sha256 VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	summary JSON NOT NULL, 
	result JSON NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_campaign_run_input UNIQUE (chain_id, data_source, input_sha256)
);
CREATE TABLE finding_transitions (
	id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	snapshot_id INTEGER, 
	from_status VARCHAR(16), 
	to_status VARCHAR(16) NOT NULL, 
	reason VARCHAR(300) NOT NULL, 
	block_number BIGINT, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id), 
	FOREIGN KEY(snapshot_id) REFERENCES wallet_snapshots (id)
);
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	address VARCHAR(42) NOT NULL, 
	fingerprint VARCHAR(66) NOT NULL, 
	rule_id VARCHAR(32) NOT NULL, 
	ruleset_version VARCHAR(32) NOT NULL, 
	category VARCHAR(64) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	severity VARCHAR(32) NOT NULL, 
	confidence VARCHAR(16) NOT NULL, 
	subject VARCHAR(200) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	explanation TEXT NOT NULL, 
	evidence JSON NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	first_seen_snapshot_id INTEGER NOT NULL, 
	first_seen_block BIGINT NOT NULL, 
	last_seen_snapshot_id INTEGER NOT NULL, 
	last_seen_block BIGINT NOT NULL, 
	resolved_block BIGINT, 
	reopen_count INTEGER NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_finding_fingerprint UNIQUE (chain_id, address, fingerprint), 
	FOREIGN KEY(first_seen_snapshot_id) REFERENCES wallet_snapshots (id), 
	FOREIGN KEY(last_seen_snapshot_id) REFERENCES wallet_snapshots (id)
);
CREATE TABLE token_transfers (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	wallet VARCHAR(42) NOT NULL, 
	token VARCHAR(42) NOT NULL, 
	sender VARCHAR(42) NOT NULL, 
	recipient VARCHAR(42) NOT NULL, 
	value VARCHAR(78) NOT NULL, 
	block_number BIGINT NOT NULL, 
	block_hash VARCHAR(66) NOT NULL, 
	transaction_hash VARCHAR(66) NOT NULL, 
	transaction_index BIGINT NOT NULL, 
	log_index BIGINT NOT NULL, 
	tx_sender VARCHAR(42), 
	data_source VARCHAR(32) NOT NULL, 
	ingested_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_token_transfer_log UNIQUE (chain_id, wallet, block_hash, log_index)
);
CREATE TABLE wallet_snapshots (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	address VARCHAR(42) NOT NULL, 
	block_number BIGINT NOT NULL, 
	block_hash VARCHAR(66) NOT NULL, 
	block_timestamp DATETIME NOT NULL, 
	head_block_number BIGINT NOT NULL, 
	created_at DATETIME NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	schema_version VARCHAR(64) NOT NULL, 
	ruleset_version VARCHAR(32) NOT NULL, 
	previous_snapshot_id INTEGER, 
	is_baseline BOOLEAN NOT NULL, 
	orphaned BOOLEAN NOT NULL, 
	token_scope JSON, 
	coverage JSON NOT NULL, 
	state JSON NOT NULL, 
	state_hash VARCHAR(66) NOT NULL, 
	changes JSON NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_wallet_snapshot_block UNIQUE (chain_id, address, block_hash, data_source), 
	FOREIGN KEY(previous_snapshot_id) REFERENCES wallet_snapshots (id)
);
CREATE TABLE wallet_transactions (
	id INTEGER NOT NULL, 
	chain_id BIGINT NOT NULL, 
	wallet VARCHAR(42) NOT NULL, 
	transaction_hash VARCHAR(66) NOT NULL, 
	block_number BIGINT NOT NULL, 
	block_hash VARCHAR(66) NOT NULL, 
	transaction_index BIGINT NOT NULL, 
	nonce BIGINT NOT NULL, 
	"to" VARCHAR(42), 
	value VARCHAR(78) NOT NULL, 
	data_source VARCHAR(32) NOT NULL, 
	ingested_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_wallet_transaction UNIQUE (chain_id, wallet, transaction_hash, block_hash)
);
CREATE INDEX ix_address_observation_wallet_block ON address_observations (chain_id, address, block_number);
CREATE INDEX ix_approval_event_owner_block ON approval_events (chain_id, owner, block_number);
CREATE INDEX ix_campaign_member_address ON campaign_memberships (address, role);
CREATE INDEX ix_campaign_run_cutoff ON campaign_runs (chain_id, data_source, cutoff_block);
CREATE INDEX ix_campaign_task_entity ON campaign_expansion_tasks (chain_id, kind, entity);
CREATE INDEX ix_finding_transition_snapshot ON finding_transitions (snapshot_id);
CREATE INDEX ix_finding_wallet_status ON findings (chain_id, address, status);
CREATE INDEX ix_token_transfer_wallet_block ON token_transfers (chain_id, wallet, block_number);
CREATE INDEX ix_wallet_snapshot_wallet_block ON wallet_snapshots (chain_id, address, block_number);
CREATE INDEX ix_wallet_transaction_wallet_block ON wallet_transactions (chain_id, wallet, block_number);
