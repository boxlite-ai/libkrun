# 阶段 12：virtio-fs 快照暂停检查点

状态：**已按用户要求暂停**（2026-10-23，Asia/Shanghai）。
开发基线：`e9cb351`。本次检查点仅包含批次 1 及审查修正；批次 2
只完成调研，没有源码改动，批次 3 尚未开始。完整镜像仍为 **v6**，
`RamSnapshotVm` 目前仍不能保存含 virtio-fs 的完整 VM。

## 已完成并审查

- fs worker 复用控制通道，在完整 FUSE 回复、used-ring 更新及中断处理后
  确认冻结，返回两个队列的游标；冻结启动和 resume 主动重查队列均已实现。
- `Fs::enable_snapshot`、`worker_control`、`snapshot_session`、
  `restore_session` 和 `activate_frozen` 已实现；状态仅对快照共享启用。
- 保存 FUSE options、node ID/lookup 引用计数、handle、有效打开标志、
  分配计数器、目录列表及 init.krun 内容引用。恢复 session 不重新 INIT。
- 目录通过独立 open file description 建立完整列表，以索引生成 cookie；
  导出不推进源游标。保存 guest inode 投影和恢复后的 ctime 覆盖。
- 七项审查修正：handle/node 对象一致性；ID 耗尽返回 EOVERFLOW；
  readdirplus 替换目录项的 inode 一致性和未交付 lookup 回收；init EOF
  边界；保留 init 的 inode 2；Fs 析构停止并 join worker；非 UTF-8 名称。
- `snapshot-fmt` 已覆盖新增 fs 模块；README 已说明接口和当前能力边界。

主要代码：`src/devices/src/virtio/fs/{device,worker,server,read_only,multikey}.rs`、
`linux/passthrough.rs`、`linux/passthrough/snapshot.rs` 和 `fs/tests.rs`。
当前恢复测试使用同一批宿主对象，**尚未证明独立副本恢复或源目录删除后恢复**。

## 已记录的验证结果

以下为 Claude worker 对最终批次 1 修正版的测试记录，Codex 已审查代码和证据。
按用户要求，后续不重复运行 worker 已完成的测试；新增改动或覆盖缺口再补测。

| 检查 | 结果 |
| --- | --- |
| `make snapshot-fmt` | 通过 |
| Linux `make snapshot-check`，含无 blk/net 的 krun-vmm 配置 | 通过 |
| Linux `make snapshot-build` | 通过 |
| Linux `snapshot_fs` | **15/15 通过** |
| Linux krun-devices 全部 snapshot 测试 | **98/98 通过** |
| Linux krun-vmm snapshot 测试 | **45 通过，48 因缺少 /dev/kvm 失败**，与基线一致 |
| macOS console / net / vsock 回归 | **26/26、20/20、16/16 通过** |
| 七项修正的反向检查 | 撤销修正后对应 7 个测试失败，恢复修正后通过 |

Linux 测试使用本地 amd64 `rust:1-bookworm` 离线容器，未挂载 `/dev/kvm`。
现有 KVM 运行结果为 **UNVERIFIED**；阶段 12 专用 KVM 用例尚未编写。
完整测试命令会因上述 KVM 用例返回失败，不能将其记为全套通过。

后续需要检查新改动时，可沿用以下容器参数执行现有 make 目标：

```sh
docker run --rm --platform linux/amd64 --network none \
  -v "$PWD:$PWD" -w "$PWD" \
  -v "$HOME/.cargo/registry:/cargo/registry:ro" \
  -v "$HOME/.cargo/config.toml:/cargo/config.toml:ro" \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR="$PWD/target/container" \
  rust:1-bookworm make snapshot-test \
  SNAPSHOT_PKGS='-p krun-devices --features blk,net' SNAPSHOT_FILTER=snapshot_fs
```

其他已用目标：`snapshot-check`、`snapshot-build`、
`snapshot-check SNAPSHOT_PKGS='-p krun-vmm'`，以及
`snapshot-test SNAPSHOT_CARGO_FLAGS='--offline --no-fail-fast'`。
macOS 原生回归需将 `KRUN_INIT_BINARY_PATH` 指向已生成的 Linux init。

## 续做顺序

### 批次 2：独立对象归档与 DAX（尚未实现）

- 跨共享按宿主文件身份去重内容，保留每个共享独立的 guest inode 投影。
  归档整个目录树和未 lookup 对象，支持文件、符号链接、硬链接、权限、
  uid/gid、时间戳、精确 xattr、char 0:0 whiteout 和打开/仅映射引用的孤儿。
- 明确拒绝 exported FD、宿主子挂载、目录多父或环、不可归档外部对象、
  FIFO/socket/其他设备节点；不能重建元数据时失败，不能静默省略。
- DAX ledger 保存文件对象、偏移、权限、匿名范围和 PROT_NONE 空洞，
  正确处理覆盖和部分解除映射；保留仅映射对象 FD。冻结同步可写映射。
- 归档源 init.krun 内容和当前私有映射字节；匿名数据仅保存排序、唯一的
  非零 4 KiB 页。恢复不使用目标编译时 init 替代内容。
- 导入通过目录 FD 和禁止跟随符号链接的操作创建独立副本；独占创建 0700
  目标目录，孤儿先打开再删除临时名字。校验先于副作用，失败只清理本次资源。
- 复制优先 O_NOATIME，保存读取前元数据，记录回退读取可能改变源 atime。
- 实测多共享、只读、rename/unlink、跨共享硬链接、两种孤儿、whiteout、
  源目录删除后恢复、独立副本、init 私有改写、DAX 覆盖/部分 unmap/空洞，
  以及畸形结构、复制/导入中途失败和清理。

已做的环境探测：默认容器支持 `user.overlay.*`；`trusted.overlay.*`
需要 `--cap-add SYS_ADMIN`。在容器内部 tmpfs 上，配合
`--cap-add SYS_ADMIN --device-cgroup-rule 'c 0:0 m'`，已实际创建 char 0:0
并设置两类 OverlayFS xattr。此为环境探测，**不是归档功能验收**。
O_PATH 符号链接通过 `/proc/self/fd/N` 读取 xattr/设置时间的操作也已探测，
包括 unlink 后的对象。建议从 `passthrough/dax.rs` 和 Linux archive 模块开始。

### 批次 3：owner、v7 格式和最终回归（尚未实现）

- 私有 `RamSnapshotVm::attach_fs(FsShareConfig)`：tag、源目录、只读、
  根目录删除选项、可选 DAX `{gpa,len}`；仅 vCPU 启动前允许调用。
  最多七共享，MMIO 从 `0xd000d000` 每次增加 4 KiB，GSI 9–15。
- 统一检查 RAM、全部设备窗口和 DAX 冲突；DAX 独立分配、额外 KVM
  memslot 并计入容量，不加入普通 RAM，保留 RAM 别名及队列校验。
- `declare_host_writers_stopped()` 仅运行且未暂停时允许声明；调用方停止
  共享及宿主别名的所有外部写入并维持至 resume。pause 保留，resume/disable
  清除；缺声明拒绝导出，导入的独占副本自动满足此前提。
- `RestoreResources::fs_dir` 当且仅当镜像含共享时提供，独占创建 0700。
- 全镜像升级 **v7**，拒绝 v1–v6；保持 16 MiB 有界 JSON，加入设备表、
  全局文件对象、共享根、FUSE 状态和映射。数据顺序为 RAM、磁盘、文件及
  init 内容、匿名映射非零页；全面检查长度、引用、范围、容量和溢出。
- 先验证结构及 RAM 队列，再创建文件；映射在 vCPU 线程前恢复。
  导出成败都保持暂停；控制不确定则禁用 owner，先停止/join 线程再释放资源。
- 补 owner 非 KVM 失败路径、全部测试编译和现有回归；提供并编译 guest
  MMIO/DAX、pending 中断、原 handle I/O、CPU 续跑用例，实际 KVM 运行
  按既定安排保留 **UNVERIFIED**。

BoxLite/shim 生命周期接入仍留在阶段 13。恢复工作应继续由 Claude worker
实施，Codex 审查；当前无正在运行的实施任务。未授权推送、PR 或部署。

## 已知边界与协调记录

- `create/mkdir/symlink/mknod/link` 在创建宿主对象后执行 lookup：node ID
  耗尽时可能留下已创建对象，但不会发出重复/保留 ID。
- 既有 `descriptor_utils` 的 descriptor 内 split 和 `write_from_at` count
  问题尚未修改；当前 FUSE 测试使用 Linux 驱动的回复布局，后续避免扩大范围。
- Orca run：`run_9438a313f694`。批次 1 与修正已完成；批次 2
  `task_d288b3b9b609` / `ctx_af1c26cdb38e` 因用户要求暂停结算为 failed，
  **并非实现或测试失败**。恢复时使用新 Dispatch，不复用已结算的生命周期 ID。
- 原终端仍可供后续使用；`worker-start --terminal` 返回 agent_unconfigured，
  当前已验证可通过 task-create、dispatch --return-preamble 和 terminal send
  投递新任务。遵循 Orca 技能要求重新确认运行态，不盲目重复启动。
