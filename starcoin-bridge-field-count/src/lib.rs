// Copyright (c) Starcoin, Inc.
// SPDX-License-Identifier: Apache-2.0

pub use starcoin_bridge_field_count_derive::*;

// Trait that provides a constant indicating the number of fields in a struct.
pub trait FieldCount {
    const FIELD_COUNT: usize;
}
