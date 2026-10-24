use super::Media;
use crate::{Error, Result, proto::media as pb};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub(crate) const GROUP_FS_METHODS: &[&str] = &[
    "group_file_list",
    "group_files",
    "group_file_info",
    "group_file_count",
    "group_file_space",
    "delete_group_file",
    "move_group_file",
    "rename_group_file",
    "create_group_folder",
    "delete_group_folder",
    "rename_group_folder",
    "move_group_folder",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFileEntry {
    pub id: String,
    pub name: String,
    pub parent_id: String,
    pub size: u64,
    pub uploaded_size: u64,
    pub bus_id: u32,
    pub upload_time: u32,
    pub expiry_time: u32,
    pub modify_time: u32,
    pub download_count: u32,
    pub uploader_uin: u64,
    pub uploader_name: String,
    pub md5: Vec<u8>,
    pub sha1: Vec<u8>,
    pub tri_sha1: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFolderEntry {
    pub id: String,
    pub parent_id: String,
    pub name: String,
    pub create_time: u32,
    pub modify_time: u32,
    pub creator_uin: u64,
    pub creator_name: String,
    pub file_count: u32,
    pub used_space: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "entry", rename_all = "snake_case")]
pub enum GroupFSEntry {
    File(GroupFileEntry),
    Folder(GroupFolderEntry),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFSPage {
    pub entries: Vec<GroupFSEntry>,
    pub is_end: bool,
    pub next_index: u32,
    pub context: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFileCount {
    pub count: u32,
    pub limit: u32,
    pub is_full: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupFileSpace {
    pub total: u64,
    pub used: u64,
}

impl Media {
    pub async fn group_file_list(
        &self,
        group_uin: u64,
        directory: &str,
        start_index: u32,
        count: u32,
        context: &[u8],
    ) -> Result<GroupFSPage> {
        if group_uin == 0 || directory.is_empty() || !(1..=1000).contains(&count) {
            return Err(Error::Malformed(
                "Invalid group filesystem page request".into(),
            ));
        }
        let request = pb::GroupFsRequest {
            list: Some(pb::GroupFsListRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                directory: Some(directory.into()),
                count: Some(count as u64),
                sort_order: Some(1),
                field_mask: Some(0xffffff),
                start_index: Some(start_index as u64),
                context: Some(context.to_vec().into()),
                client_type: Some(2),
                list_flag: Some(0),
            }),
            ..Default::default()
        };
        let response: pb::GroupFsResponse = self.oidb(0x6d8, 1, request, 1, None).await?;
        let page = response
            .list
            .ok_or_else(|| Error::Malformed("Missing protobuf field 2".into()))?;
        fs_result(page.result_code, page.result_message.clone())?;
        decode_page(&page, start_index, context)
    }
    pub async fn group_files(&self, group_uin: u64, directory: &str) -> Result<Vec<GroupFSEntry>> {
        let mut entries = Vec::new();
        let mut index = 0;
        let mut context = Vec::new();
        let mut seen = HashSet::new();
        loop {
            if !seen.insert((index, context.clone())) {
                return Err(Error::Malformed(
                    "Group filesystem repeated a continuation".into(),
                ));
            }
            let page = self
                .group_file_list(group_uin, directory, index, 100, &context)
                .await?;
            entries.extend(page.entries);
            if page.is_end {
                return Ok(entries);
            }
            index = page.next_index;
            context = page.context;
            tokio::task::yield_now().await;
        }
    }
    pub async fn group_file_info(&self, group_uin: u64, file_id: &str) -> Result<GroupFileEntry> {
        file_identity(group_uin, file_id)?;
        let request = pb::GroupFsRequest {
            info: Some(pb::GroupFsInfoRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                bus_id: Some(102),
                file_id: Some(file_id.into()),
                field_mask: Some(0xffffff),
            }),
            ..Default::default()
        };
        let response: pb::GroupFsResponse = self.oidb(0x6d8, 0, request, 0, None).await?;
        let result = response
            .info
            .ok_or_else(|| Error::Malformed("Missing protobuf field 1".into()))?;
        fs_result(result.result_code, result.result_message)?;
        group_file_entry(
            &result
                .file
                .ok_or_else(|| Error::Malformed("Missing protobuf field 4".into()))?,
        )
    }
    pub async fn group_file_count(&self, group_uin: u64) -> Result<GroupFileCount> {
        group_identity(group_uin)?;
        let request = pb::GroupFsRequest {
            count: Some(pb::GroupFsCountRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                bus_id: Some(6),
            }),
            ..Default::default()
        };
        let response: pb::GroupFsResponse = self.oidb(0x6d8, 2, request, 1, Some(1)).await?;
        let count = response
            .count
            .ok_or_else(|| Error::Malformed("Missing protobuf field 3".into()))?;
        fs_result(count.result_code, count.result_message)?;
        Ok(GroupFileCount {
            count: count.count.unwrap_or_default() as u32,
            limit: count.limit.unwrap_or_default() as u32,
            is_full: count.is_full.unwrap_or_default() != 0,
        })
    }
    pub async fn group_file_space(&self, group_uin: u64) -> Result<GroupFileSpace> {
        group_identity(group_uin)?;
        let request = pb::GroupFsRequest {
            space: Some(pb::GroupFsSpaceRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
            }),
            ..Default::default()
        };
        let response: pb::GroupFsResponse = self.oidb(0x6d8, 3, request, 1, Some(1)).await?;
        let space = response
            .space
            .ok_or_else(|| Error::Malformed("Missing protobuf field 4".into()))?;
        fs_result(space.result_code, space.result_message)?;
        Ok(GroupFileSpace {
            total: space.total.unwrap_or_default(),
            used: space.used.unwrap_or_default(),
        })
    }
    pub async fn delete_group_file(
        &self,
        group_uin: u64,
        file_id: &str,
        parent_directory: &str,
    ) -> Result<()> {
        file_identity(group_uin, file_id)?;
        let request = pb::GroupFileCommandRequest {
            delete: Some(pb::GroupFileDeleteRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                bus_id: Some(102),
                parent_directory: Some(parent_directory.into()),
                file_id: Some(file_id.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupFileCommandResponse = self.oidb(0x6d6, 3, request, 0, None).await?;
        let result = response
            .delete
            .ok_or_else(|| Error::Malformed("Missing protobuf field 4".into()))?;
        fs_result(result.result_code, result.result_message)
    }
    pub async fn move_group_file(
        &self,
        group_uin: u64,
        file_id: &str,
        parent_directory: &str,
        destination_directory: &str,
    ) -> Result<()> {
        file_identity(group_uin, file_id)?;
        let request = pb::GroupFileCommandRequest {
            r#move: Some(pb::GroupFileMoveRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                bus_id: Some(102),
                file_id: Some(file_id.into()),
                parent_directory: Some(parent_directory.into()),
                destination_directory: Some(destination_directory.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupFileCommandResponse = self.oidb(0x6d6, 5, request, 0, None).await?;
        let result = response
            .r#move
            .ok_or_else(|| Error::Malformed("Missing protobuf field 6".into()))?;
        fs_result(result.result_code, result.result_message)
    }
    pub async fn rename_group_file(
        &self,
        group_uin: u64,
        file_id: &str,
        parent_directory: &str,
        name: &str,
    ) -> Result<()> {
        if name.is_empty() {
            return Err(Error::Malformed("Empty file name".into()));
        }
        file_identity(group_uin, file_id)?;
        let request = pb::GroupFileCommandRequest {
            rename: Some(pb::GroupFileRenameRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                bus_id: Some(102),
                file_id: Some(file_id.into()),
                parent_directory: Some(parent_directory.into()),
                name: Some(name.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupFileCommandResponse = self.oidb(0x6d6, 4, request, 0, None).await?;
        let result = response
            .rename
            .ok_or_else(|| Error::Malformed("Missing protobuf field 5".into()))?;
        fs_result(result.result_code, result.result_message)
    }
    pub async fn create_group_folder(
        &self,
        group_uin: u64,
        name: &str,
        parent_directory: &str,
    ) -> Result<Option<GroupFolderEntry>> {
        if name.is_empty() || parent_directory.is_empty() {
            return Err(Error::Malformed("Empty group folder name/parent".into()));
        }
        group_identity(group_uin)?;
        let request = pb::GroupDirectoryRequest {
            create: Some(pb::GroupDirectoryCreateRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                parent_directory: Some(parent_directory.into()),
                name: Some(name.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupDirectoryResponse = self.oidb(0x6d7, 0, request, 0, None).await?;
        let result = response
            .create
            .ok_or_else(|| Error::Malformed("Missing protobuf field 1".into()))?;
        fs_result(result.result_code, result.result_message)?;
        result.folder.as_ref().map(group_folder_entry).transpose()
    }
    pub async fn delete_group_folder(&self, group_uin: u64, folder_id: &str) -> Result<()> {
        if folder_id.is_empty() || folder_id == "/" {
            return Err(Error::Malformed("Cannot delete the root folder".into()));
        }
        group_identity(group_uin)?;
        let request = pb::GroupDirectoryRequest {
            delete: Some(pb::GroupDirectoryDeleteRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                folder_id: Some(folder_id.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupDirectoryResponse = self.oidb(0x6d7, 1, request, 0, None).await?;
        let result = response
            .delete
            .ok_or_else(|| Error::Malformed("Missing protobuf field 2".into()))?;
        fs_result(result.result_code, result.result_message)?;
        Ok(())
    }
    pub async fn rename_group_folder(
        &self,
        group_uin: u64,
        folder_id: &str,
        name: &str,
    ) -> Result<Option<GroupFolderEntry>> {
        if folder_id.is_empty() || name.is_empty() {
            return Err(Error::Malformed("Empty group folder identity/name".into()));
        }
        group_identity(group_uin)?;
        let request = pb::GroupDirectoryRequest {
            rename: Some(pb::GroupDirectoryRenameRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                folder_id: Some(folder_id.into()),
                name: Some(name.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupDirectoryResponse = self.oidb(0x6d7, 2, request, 0, None).await?;
        let result = response
            .rename
            .ok_or_else(|| Error::Malformed("Missing protobuf field 3".into()))?;
        fs_result(result.result_code, result.result_message)?;
        result.folder.as_ref().map(group_folder_entry).transpose()
    }
    pub async fn move_group_folder(
        &self,
        group_uin: u64,
        folder_id: &str,
        parent_directory: &str,
        destination_directory: &str,
    ) -> Result<Option<GroupFolderEntry>> {
        if folder_id.is_empty()
            || folder_id == "/"
            || parent_directory.is_empty()
            || destination_directory.is_empty()
            || folder_id == destination_directory
        {
            return Err(Error::Malformed("Invalid group folder move".into()));
        }
        group_identity(group_uin)?;
        let request = pb::GroupDirectoryRequest {
            r#move: Some(pb::GroupDirectoryMoveRequest {
                group_uin: Some(group_uin),
                app_id: Some(7),
                folder_id: Some(folder_id.into()),
                parent_directory: Some(parent_directory.into()),
                destination_directory: Some(destination_directory.into()),
            }),
            ..Default::default()
        };
        let response: pb::GroupDirectoryResponse = self.oidb(0x6d7, 3, request, 0, None).await?;
        let result = response
            .r#move
            .ok_or_else(|| Error::Malformed("Missing protobuf field 4".into()))?;
        fs_result(result.result_code, result.result_message)?;
        result.folder.as_ref().map(group_folder_entry).transpose()
    }
    pub(crate) async fn dispatch_group_fs(&self, method: &str, args: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct Args {
            group_uin: u64,
            #[serde(default = "root")]
            directory: String,
            #[serde(default)]
            start_index: u32,
            #[serde(default = "page_size")]
            count: u32,
            #[serde(default)]
            context: Vec<u8>,
            #[serde(default)]
            file_id: String,
            #[serde(default)]
            folder_id: String,
            #[serde(default)]
            name: String,
            #[serde(default = "root")]
            parent_directory: String,
            #[serde(default)]
            destination_directory: String,
        }
        if !GROUP_FS_METHODS.contains(&method) {
            return Err(Error::Unsupported(format!(
                "Unknown group filesystem method: {method}"
            )));
        }
        let a: Args = serde_json::from_value(args).map_err(|e| Error::Malformed(e.to_string()))?;
        fn value<T: Serialize>(v: T) -> Result<Value> {
            serde_json::to_value(v).map_err(|e| Error::Malformed(e.to_string()))
        }
        match method {
            "group_file_list" => value(
                self.group_file_list(
                    a.group_uin,
                    &a.directory,
                    a.start_index,
                    a.count,
                    &a.context,
                )
                .await?,
            ),
            "group_files" => value(self.group_files(a.group_uin, &a.directory).await?),
            "group_file_info" => value(self.group_file_info(a.group_uin, &a.file_id).await?),
            "group_file_count" => value(self.group_file_count(a.group_uin).await?),
            "group_file_space" => value(self.group_file_space(a.group_uin).await?),
            "delete_group_file" => value(
                self.delete_group_file(a.group_uin, &a.file_id, &a.parent_directory)
                    .await?,
            ),
            "move_group_file" => value(
                self.move_group_file(
                    a.group_uin,
                    &a.file_id,
                    &a.parent_directory,
                    &a.destination_directory,
                )
                .await?,
            ),
            "rename_group_file" => value(
                self.rename_group_file(a.group_uin, &a.file_id, &a.parent_directory, &a.name)
                    .await?,
            ),
            "create_group_folder" => value(
                self.create_group_folder(a.group_uin, &a.name, &a.parent_directory)
                    .await?,
            ),
            "delete_group_folder" => {
                value(self.delete_group_folder(a.group_uin, &a.folder_id).await?)
            }
            "rename_group_folder" => value(
                self.rename_group_folder(a.group_uin, &a.folder_id, &a.name)
                    .await?,
            ),
            "move_group_folder" => value(
                self.move_group_folder(
                    a.group_uin,
                    &a.folder_id,
                    &a.parent_directory,
                    &a.destination_directory,
                )
                .await?,
            ),
            _ => Err(Error::Unsupported(format!(
                "Unknown group filesystem method: {method}"
            ))),
        }
    }
}
fn root() -> String {
    "/".into()
}
fn page_size() -> u32 {
    100
}
fn group_identity(group_uin: u64) -> Result<()> {
    if group_uin == 0 {
        Err(Error::Malformed("Invalid group UIN".into()))
    } else {
        Ok(())
    }
}
fn file_identity(group_uin: u64, file_id: &str) -> Result<()> {
    group_identity(group_uin)?;
    if file_id.is_empty() {
        Err(Error::Malformed("Invalid group file identity".into()))
    } else {
        Ok(())
    }
}
fn decode_page(
    page: &pb::GroupFsListResponse,
    start_index: u32,
    context: &[u8],
) -> Result<GroupFSPage> {
    let mut entries = Vec::with_capacity(page.entries.len());
    for item in &page.entries {
        entries.push(match item.entry_type.unwrap_or_default() {
            1 => GroupFSEntry::File(group_file_entry(
                item.file
                    .as_ref()
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 3".into()))?,
            )?),
            2 => GroupFSEntry::Folder(group_folder_entry(
                item.folder
                    .as_ref()
                    .ok_or_else(|| Error::Malformed("Missing protobuf field 2".into()))?,
            )?),
            kind => {
                return Err(Error::Unsupported(format!(
                    "Unknown group filesystem entry type {kind}"
                )));
            }
        });
    }
    let next_index = page
        .next_index
        .map(|v| v as u32)
        .unwrap_or_else(|| (start_index as u64 + entries.len() as u64) as u32);
    let is_end = page.is_end.unwrap_or_default() != 0;
    let next_context = page.context.as_deref().unwrap_or_default().to_vec();
    if !is_end && next_index <= start_index && next_context == context {
        return Err(Error::Malformed(
            "Group filesystem pagination did not advance".into(),
        ));
    }
    Ok(GroupFSPage {
        entries,
        is_end,
        next_index,
        context: next_context,
    })
}
fn group_file_entry(v: &pb::GroupFsFile) -> Result<GroupFileEntry> {
    let id = fs_text(v.id.as_deref())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::Malformed("Group file entry has no ID".into()))?;
    Ok(GroupFileEntry {
        id,
        name: fs_text(v.name.as_deref()).unwrap_or_default(),
        parent_id: fs_text(v.parent_id.as_deref()).unwrap_or_else(root),
        size: v.size.unwrap_or_default(),
        uploaded_size: v.uploaded_size.unwrap_or_default(),
        bus_id: v.bus_id.unwrap_or_default() as u32,
        upload_time: v.upload_time.unwrap_or_default() as u32,
        expiry_time: v.expiry_time.unwrap_or_default() as u32,
        modify_time: v.modify_time.unwrap_or_default() as u32,
        download_count: v.download_count.unwrap_or_default() as u32,
        uploader_uin: v.uploader_uin.unwrap_or_default(),
        uploader_name: fs_text(v.uploader_name.as_deref()).unwrap_or_default(),
        md5: v.md5.as_deref().unwrap_or_default().to_vec(),
        sha1: v.sha1.as_deref().unwrap_or_default().to_vec(),
        tri_sha1: v.tri_sha1.as_deref().unwrap_or_default().to_vec(),
    })
}
fn group_folder_entry(v: &pb::GroupFsFolder) -> Result<GroupFolderEntry> {
    let id = fs_text(v.id.as_deref())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::Malformed("Group folder entry has no ID".into()))?;
    Ok(GroupFolderEntry {
        id,
        parent_id: fs_text(v.parent_id.as_deref()).unwrap_or_else(root),
        name: fs_text(v.name.as_deref()).unwrap_or_default(),
        create_time: v.create_time.unwrap_or_default() as u32,
        modify_time: v.modify_time.unwrap_or_default() as u32,
        creator_uin: v.creator_uin.unwrap_or_default(),
        creator_name: fs_text(v.creator_name.as_deref()).unwrap_or_default(),
        file_count: v.file_count.unwrap_or_default() as u32,
        used_space: v.used_space.unwrap_or_default(),
    })
}

fn fs_result(code: Option<u64>, message: Option<bytes::Bytes>) -> Result<()> {
    let code = code.unwrap_or_default() as i32;
    if code != 0 {
        Err(Error::Server {
            code,
            message: fs_text(message.as_deref()).unwrap_or_else(|| "QQ request failed".into()),
        })
    } else {
        Ok(())
    }
}

fn fs_text(value: Option<&[u8]>) -> Option<String> {
    value
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filesystem_metadata_keeps_invalid_text_as_absent() {
        let entry = group_file_entry(&pb::GroupFsFile {
            id: Some("file-id".into()),
            name: Some(vec![0xff].into()),
            parent_id: Some(vec![0xff].into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(entry.name, "");
        assert_eq!(entry.parent_id, "/");
        assert!(
            group_folder_entry(&pb::GroupFsFolder {
                id: Some(vec![0xff].into()),
                ..Default::default()
            })
            .is_err()
        );
        assert!(matches!(
            fs_result(Some(7), Some(vec![0xff].into())),
            Err(Error::Server { code: 7, message }) if message == "QQ request failed"
        ));
    }

    #[test]
    fn page_requires_progress_unless_finished() {
        let mut page = pb::GroupFsListResponse::default();
        assert!(decode_page(&page, 0, &[]).is_err());
        page.is_end = Some(1);
        assert!(decode_page(&page, 0, &[]).unwrap().is_end);
        let continuation = pb::GroupFsListResponse {
            context: Some(vec![1].into()),
            ..Default::default()
        };
        assert_eq!(decode_page(&continuation, 0, &[]).unwrap().context, vec![1]);
        assert!(decode_page(&continuation, 0, &[1]).is_err());
    }
    #[test]
    fn page_fallback_advances_by_entry_count_and_preserves_file_fields() {
        let page = pb::GroupFsListResponse {
            entries: vec![pb::GroupFsEntry {
                entry_type: Some(1),
                file: Some(pb::GroupFsFile {
                    id: Some("file-id".into()),
                    name: Some("name".into()),
                    size: Some(1 << 40),
                    uploader_uin: Some(123),
                    md5: Some(vec![1, 2].into()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let decoded = decode_page(&page, 7, &[]).unwrap();
        assert_eq!(decoded.next_index, 8);
        let GroupFSEntry::File(file) = &decoded.entries[0] else {
            panic!("expected file")
        };
        assert_eq!(file.size, 1 << 40);
        assert_eq!(file.parent_id, "/");
        assert_eq!(file.md5, vec![1, 2]);
        let encoded = serde_json::to_value(&decoded).unwrap();
        assert_eq!(
            serde_json::from_value::<GroupFSPage>(encoded).unwrap(),
            decoded
        );
    }
    #[test]
    fn page_rejects_unknown_and_missing_entry_identity() {
        let page = pb::GroupFsListResponse {
            entries: vec![pb::GroupFsEntry {
                entry_type: Some(42),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            decode_page(&page, 0, &[]),
            Err(Error::Unsupported(_))
        ));
        assert!(group_file_entry(&pb::GroupFsFile::default()).is_err());
        assert!(group_folder_entry(&pb::GroupFsFolder::default()).is_err());
    }
    #[test]
    fn page_accepts_context_only_and_index_only_progress() {
        let page = pb::GroupFsListResponse {
            next_index: Some(9),
            ..Default::default()
        };
        assert_eq!(decode_page(&page, 8, &[]).unwrap().next_index, 9);
        let page = pb::GroupFsListResponse {
            next_index: Some(8),
            context: Some(vec![2].into()),
            ..Default::default()
        };
        assert!(decode_page(&page, 8, &[1]).is_ok());
    }
}
