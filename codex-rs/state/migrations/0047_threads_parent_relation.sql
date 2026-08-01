ALTER TABLE threads ADD COLUMN parent_thread_id TEXT;
ALTER TABLE threads ADD COLUMN parent_thread_id_known INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_threads_parent_thread_id
    ON threads(parent_thread_id);
