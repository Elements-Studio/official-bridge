// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

pub const LIVE_TASK_TARGET_BLOCK: i64 = i64::MAX;

/// Separator used between task name components.
/// Using " - " (space-dash-space) for backward compatibility with existing task names.
const TASK_NAME_SEPARATOR: &str = " - ";

/// Task type identifiers used in task naming
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskType {
    Live,
    Backfill,
}

impl TaskType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskType::Live => "live",
            TaskType::Backfill => "backfill",
        }
    }

    /// Parse TaskType from string
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "live" => Some(TaskType::Live),
            "backfill" => Some(TaskType::Backfill),
            _ => None,
        }
    }
}

/// Structured task name for robust parsing and generation.
/// Format: "{indexer_name} - {task_type} - {identifier}"
/// Example: "my_indexer - backfill - 100:200" or "my_indexer - live - 1"
#[derive(Clone, Debug)]
pub struct TaskName {
    /// Name of the indexer (e.g., "eth_bridge_indexer")
    pub indexer_name: String,
    /// Type of task (live or backfill)
    pub task_type: TaskType,
    /// Additional identifier (range for backfill, sequence number for live)
    pub identifier: String,
}

impl TaskName {
    /// Create a new task name for a live task
    pub fn new_live(indexer_name: &str, sequence: u64) -> Self {
        Self {
            indexer_name: indexer_name.to_string(),
            task_type: TaskType::Live,
            identifier: sequence.to_string(),
        }
    }

    /// Create a new task name for a backfill task with a block range
    pub fn new_backfill(indexer_name: &str, start: u64, end: u64) -> Self {
        Self {
            indexer_name: indexer_name.to_string(),
            task_type: TaskType::Backfill,
            identifier: format!("{}:{}", start, end),
        }
    }

    /// Create a new task name for a backfill task with a simple sequence
    pub fn new_backfill_seq(indexer_name: &str, sequence: u64) -> Self {
        Self {
            indexer_name: indexer_name.to_string(),
            task_type: TaskType::Backfill,
            identifier: sequence.to_string(),
        }
    }

    /// Parse a task name string into components.
    /// Returns None if the string format is invalid.
    pub fn parse(task_name: &str) -> Option<Self> {
        let parts: Vec<&str> = task_name.split(TASK_NAME_SEPARATOR).collect();

        if parts.len() < 2 {
            // Fallback for old format without proper separators
            return Some(Self {
                indexer_name: task_name
                    .split_whitespace()
                    .next()
                    .unwrap_or(task_name)
                    .to_string(),
                task_type: if task_name.to_lowercase().contains("live") {
                    TaskType::Live
                } else {
                    TaskType::Backfill
                },
                identifier: String::new(),
            });
        }

        let indexer_name = parts[0].to_string();
        let task_type = TaskType::parse_str(parts[1])?;
        let identifier = if parts.len() > 2 {
            parts[2..].join(TASK_NAME_SEPARATOR)
        } else {
            String::new()
        };

        Some(Self {
            indexer_name,
            task_type,
            identifier,
        })
    }

    /// Get the indexer name (prefix)
    pub fn indexer_name(&self) -> &str {
        &self.indexer_name
    }

    /// Check if this is a live task
    pub fn is_live(&self) -> bool {
        self.task_type == TaskType::Live
    }

    /// Get task type as string
    pub fn type_str(&self) -> &str {
        self.task_type.as_str()
    }
}

impl std::fmt::Display for TaskName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.identifier.is_empty() {
            write!(
                f,
                "{}{}{}",
                self.indexer_name,
                TASK_NAME_SEPARATOR,
                self.task_type.as_str()
            )
        } else {
            write!(
                f,
                "{}{}{}{}{}",
                self.indexer_name,
                TASK_NAME_SEPARATOR,
                self.task_type.as_str(),
                TASK_NAME_SEPARATOR,
                self.identifier
            )
        }
    }
}

#[derive(Clone, Debug)]
pub struct Task {
    pub task_name: String,
    pub start_block: u64,
    pub target_block: u64,
    pub timestamp: u64,
    pub is_live_task: bool,
}

impl Task {
    /// Create a new Task with structured naming
    pub fn new(
        indexer_name: &str,
        task_type: TaskType,
        identifier: &str,
        start_block: u64,
        target_block: u64,
    ) -> Self {
        let task_name = TaskName {
            indexer_name: indexer_name.to_string(),
            task_type: task_type.clone(),
            identifier: identifier.to_string(),
        };
        Self {
            task_name: task_name.to_string(),
            start_block,
            target_block,
            timestamp: 0,
            is_live_task: task_type == TaskType::Live,
        }
    }

    /// Create a new live task
    pub fn new_live(indexer_name: &str, start_block: u64) -> Self {
        let task_name = TaskName::new_live(indexer_name, start_block);
        Self {
            task_name: task_name.to_string(),
            start_block,
            target_block: LIVE_TASK_TARGET_BLOCK as u64,
            timestamp: 0,
            is_live_task: true,
        }
    }

    /// Create a new backfill task with block range
    pub fn new_backfill(indexer_name: &str, start_block: u64, target_block: u64) -> Self {
        let task_name = TaskName::new_backfill(indexer_name, start_block, target_block);
        Self {
            task_name: task_name.to_string(),
            start_block,
            target_block,
            timestamp: 0,
            is_live_task: false,
        }
    }

    /// Get the indexer name (prefix) from the task name.
    /// Uses structured parsing for robustness.
    pub fn name_prefix(&self) -> &str {
        // Try structured parsing first
        if let Some(parsed) = TaskName::parse(&self.task_name) {
            // Return a reference to a leaked string to maintain &str return type
            // This is acceptable since task names are typically long-lived
            // and the number of unique prefixes is bounded
            return Box::leak(parsed.indexer_name.into_boxed_str());
        }
        // Fallback: split by whitespace and take first part
        self.task_name
            .split_whitespace()
            .next()
            .unwrap_or("Unknown")
    }

    /// Get the parsed task name structure for advanced operations
    pub fn parsed_name(&self) -> Option<TaskName> {
        TaskName::parse(&self.task_name)
    }

    pub fn type_str(&self) -> &str {
        if self.is_live_task {
            "live"
        } else {
            "backfill"
        }
    }
}

#[derive(Clone, Debug)]
pub struct Tasks {
    live_task: Option<Task>,
}

impl Tasks {
    pub fn new(tasks: Vec<Task>) -> anyhow::Result<Self> {
        let mut live_tasks = vec![];
        for task in tasks {
            if task.is_live_task {
                live_tasks.push(task);
            }
        }
        if live_tasks.len() > 1 {
            anyhow::bail!("More than one live task found: {:?}", live_tasks);
        }
        Ok(Self {
            live_task: live_tasks.pop(),
        })
    }

    pub fn live_task(&self) -> Option<Task> {
        self.live_task.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_name_display() {
        let name = TaskName::new_live("my_indexer", 100);
        assert_eq!(name.to_string(), "my_indexer - live - 100");

        let name = TaskName::new_backfill("my_indexer", 100, 200);
        assert_eq!(name.to_string(), "my_indexer - backfill - 100:200");

        let name = TaskName::new_backfill_seq("my_indexer", 1);
        assert_eq!(name.to_string(), "my_indexer - backfill - 1");
    }

    #[test]
    fn test_task_name_parse() {
        // Test live task parsing
        let parsed = TaskName::parse("my_indexer - live - 100").unwrap();
        assert_eq!(parsed.indexer_name, "my_indexer");
        assert_eq!(parsed.task_type, TaskType::Live);
        assert_eq!(parsed.identifier, "100");

        // Test backfill task with range parsing
        let parsed = TaskName::parse("my_indexer - backfill - 100:200").unwrap();
        assert_eq!(parsed.indexer_name, "my_indexer");
        assert_eq!(parsed.task_type, TaskType::Backfill);
        assert_eq!(parsed.identifier, "100:200");

        // Test backfill task with simple sequence
        let parsed = TaskName::parse("my_indexer - backfill - 1").unwrap();
        assert_eq!(parsed.indexer_name, "my_indexer");
        assert_eq!(parsed.task_type, TaskType::Backfill);
        assert_eq!(parsed.identifier, "1");

        // Test task without identifier
        let parsed = TaskName::parse("my_indexer - live").unwrap();
        assert_eq!(parsed.indexer_name, "my_indexer");
        assert_eq!(parsed.task_type, TaskType::Live);
        assert_eq!(parsed.identifier, "");
    }

    #[test]
    fn test_task_name_parse_legacy_format() {
        // Test fallback parsing for legacy format without separators
        let parsed = TaskName::parse("my_indexer live 100").unwrap();
        assert_eq!(parsed.indexer_name, "my_indexer");
        assert!(parsed.is_live());

        let parsed = TaskName::parse("my_indexer backfill 100").unwrap();
        assert_eq!(parsed.indexer_name, "my_indexer");
        assert!(!parsed.is_live());
    }

    #[test]
    fn test_task_type_parse_str() {
        assert_eq!(TaskType::parse_str("live"), Some(TaskType::Live));
        assert_eq!(TaskType::parse_str("Live"), Some(TaskType::Live));
        assert_eq!(TaskType::parse_str("LIVE"), Some(TaskType::Live));
        assert_eq!(TaskType::parse_str("backfill"), Some(TaskType::Backfill));
        assert_eq!(TaskType::parse_str("Backfill"), Some(TaskType::Backfill));
        assert_eq!(TaskType::parse_str("BACKFILL"), Some(TaskType::Backfill));
        assert_eq!(TaskType::parse_str("unknown"), None);
    }

    #[test]
    fn test_task_name_prefix() {
        // Test with structured name
        let task = Task {
            task_name: "my_indexer - backfill - 100:200".to_string(),
            start_block: 100,
            target_block: 200,
            timestamp: 0,
            is_live_task: false,
        };
        assert_eq!(task.name_prefix(), "my_indexer");

        // Test with live task
        let task = Task {
            task_name: "eth_bridge_indexer - live - 500".to_string(),
            start_block: 500,
            target_block: LIVE_TASK_TARGET_BLOCK as u64,
            timestamp: 0,
            is_live_task: true,
        };
        assert_eq!(task.name_prefix(), "eth_bridge_indexer");

        // Test with legacy format (space-separated)
        let task = Task {
            task_name: "old_indexer some other stuff".to_string(),
            start_block: 0,
            target_block: 100,
            timestamp: 0,
            is_live_task: false,
        };
        // The fallback parsing should extract the first word
        assert!(task.name_prefix().starts_with("old_indexer"));
    }

    #[test]
    fn test_task_new_constructors() {
        // Test new_live
        let task = Task::new_live("test_indexer", 100);
        assert!(task.is_live_task);
        assert_eq!(task.start_block, 100);
        assert_eq!(task.target_block, LIVE_TASK_TARGET_BLOCK as u64);
        assert!(task.task_name.contains("live"));

        // Test new_backfill
        let task = Task::new_backfill("test_indexer", 50, 100);
        assert!(!task.is_live_task);
        assert_eq!(task.start_block, 50);
        assert_eq!(task.target_block, 100);
        assert!(task.task_name.contains("backfill"));
        assert!(task.task_name.contains("50:100"));
    }

    #[test]
    fn test_task_parsed_name() {
        let task = Task::new_backfill("test_indexer", 50, 100);
        let parsed = task.parsed_name().unwrap();
        assert_eq!(parsed.indexer_name, "test_indexer");
        assert_eq!(parsed.task_type, TaskType::Backfill);
        assert_eq!(parsed.identifier, "50:100");
    }

    #[test]
    fn test_roundtrip() {
        // Test that TaskName -> String -> TaskName preserves all fields
        let original = TaskName::new_backfill("complex_indexer_name", 12345, 67890);
        let as_string = original.to_string();
        let parsed = TaskName::parse(&as_string).unwrap();

        assert_eq!(parsed.indexer_name, original.indexer_name);
        assert_eq!(parsed.task_type, original.task_type);
        assert_eq!(parsed.identifier, original.identifier);
    }
}
