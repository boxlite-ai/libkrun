// SPDX-License-Identifier: Apache-2.0

//! Host resources for version-9 checkpoints. Paths name pre-mounted share roots only.
use devices::virtio::fs::passthrough::RestoredRoles;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReference {
    pub resource_id: String,
    pub recovery_point: String,
    pub object_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportMetadata {
    pub application_schema: u32,
    pub application: serde_json::Value,
    /// One reference per retained object, in prepared share/object order.
    pub objects: Vec<Vec<ExternalReference>>,
}

pub struct PreparedResources {
    /// Dependency metadata. FDs correspond to its shares' retained objects, in order.
    pub metadata: Vec<u8>,
    pub files: Vec<File>,
}

pub struct ShareBinding {
    pub root: PathBuf,
    /// Pinned O_PATH descriptors in saved object order; None marks a missing orphan.
    pub objects: Vec<Option<File>>,
    pub roles: RestoredRoles,
}

/// Disks follow saved guest order: writable standalone QCOW2 or exact readonly boot.
#[derive(Default)]
pub struct ImportBindings {
    pub disks: Vec<File>,
    pub shares: Vec<ShareBinding>,
}

/// C ABI JSON descriptor indices. Every received FD must be used exactly once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingIndices {
    pub disks: Vec<usize>,
    pub shares: Vec<ShareIndices>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareIndices {
    pub root: PathBuf,
    pub objects: Vec<Option<usize>>,
    pub handles: BTreeMap<u64, usize>,
    pub dax: Vec<DaxIndex>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaxIndex {
    pub object: u64,
    pub writable: bool,
    pub fd: usize,
}
impl BindingIndices {
    pub fn bind(self, files: Vec<File>) -> Result<ImportBindings, &'static str> {
        let mut files: Vec<_> = files.into_iter().map(Some).collect();
        let mut take = |index: usize| {
            files
                .get_mut(index)
                .and_then(Option::take)
                .ok_or("missing or reused descriptor index")
        };
        let disks = self
            .disks
            .into_iter()
            .map(&mut take)
            .collect::<Result<_, _>>()?;
        let mut shares = Vec::new();
        for share in self.shares {
            if !share.root.is_absolute() {
                return Err("share root must be absolute");
            }
            let objects = share
                .objects
                .into_iter()
                .map(|index| index.map(&mut take).transpose())
                .collect::<Result<_, _>>()?;
            let handles = share
                .handles
                .into_iter()
                .map(|(id, fd)| Ok((id, take(fd)?)))
                .collect::<Result<_, &'static str>>()?;
            let mut dax = BTreeMap::new();
            for role in share.dax {
                if dax
                    .insert((role.object, role.writable), take(role.fd)?)
                    .is_some()
                {
                    return Err("duplicate DAX role");
                }
            }
            shares.push(ShareBinding {
                root: share.root,
                objects,
                roles: RestoredRoles { handles, dax },
            });
        }
        if files.iter().any(Option::is_some) {
            return Err("unused descriptor");
        }
        Ok(ImportBindings { disks, shares })
    }
}
