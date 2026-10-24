# 阶段 12：virtio-fs 内部快照检查点

状态：阶段 12 **已完成，全部审查通过并在本地提交**。批次 1 及审查修正
（`32dc08f`）；批次 2 的 DAX ledger 与 fail-closed 审查修正（`c79d6ff`）、
独立对象归档及其四项审查修正（`bb0617d`）；批次 3（owner、完整镜像
**v7**）及其 DAX 执行屏障修正在其后的阶段 12 收尾提交中。内部
`RamSnapshotVm` 可通过 `declare_host_writers_stopped`、`attach_fs`、
`pause`、`export`、`import`、`resume` 保存和恢复含最多七个 virtio-fs 共享的
完整 VM；无公共 C ABI、SDK 或 CLI 入口。需要 VM 的路径仅编译，KVM 实际
运行为 **UNVERIFIED**；没有真实 BoxLite/shim 恢复，接入属于阶段 13（未来
工作）。验证边界见下文“最终验证与边界”。

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
（批次 1 时的记录：恢复测试使用同一批宿主对象，尚未证明独立副本恢复。
批次 2 的归档测试与批次 3 的 `snapshot_fs_vmm` 测试已覆盖源目录删除后在
独立副本上继续。）

## 已记录的验证结果

以下为批次 1 修正版的历史测试记录（Claude worker 执行，Codex 已审查）。
最终结果见“最终验证与边界”。
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
现有 KVM 运行结果为 **UNVERIFIED**；批次 1 时阶段 12 专用 KVM 用例尚未
编写（批次 3 已编写，仅编译）。
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

### 批次 2 第一部分：DAX ledger（已审查通过）

`linux/passthrough/dax.rs`，仅快照共享启用；普通共享的映射代码未改动。

- 宿主映射成功后才更新 ledger。窗口划分为文件映射（对象、文件偏移、
  只读/可写）、私有匿名内存（初始可读写；init.krun 副本按请求的文件
  偏移复制共享的 init 字节并按请求权限设置）和 PROT_NONE 空洞。覆盖与
  部分解除映射切分已有段并保留每个字节的文件偏移；多范围解除映射在
  失败处停止，之前成功的范围保留在 ledger 中。
- 首个请求绑定窗口，要求整页、页对齐且不溢出地址空间；所有偏移检查
  均无溢出。每个文件映射持有自己的描述符（按对象和权限共享），仅被映射
  引用的对象（节点已 forget、名字已 unlink）进入检查点对象表。
- 冻结在确认前对可写文件映射执行 `msync(MS_SYNC)`。
- fail-closed（审查修正）：宿主会直接拒绝的请求（窗口外、文件偏移未对齐、
  非普通文件、未知节点）在任何宿主调用前拒绝，窗口仍可用。宿主
  `mmap`/`mprotect` 仍失败时（`MAP_FIXED` 可能先解除旧映射再失败，
  `mprotect` 可能中途停止）宿主布局不确定，窗口记为丢失：之后的映射请求
  与 `sync_for_snapshot` 返回 `EIO`（freeze 因此报错而不确认），捕获返回
  `PassthroughSnapshotError::DaxLost`，均不触碰窗口内存；owner 须丢弃
  共享（停止并 join worker），不做回滚。`map_dax` 中途失败时窗口记为
  丢失、设备退役（批次 3 起；此前仅约定由调用方丢弃）。`Fs::restore_session` 在没有
  DAX 状态/窗口时拒绝非空 `dax_pages`，且早于构建 session。
- 接口：`PassthroughState::dax: Option<DaxState>`（映射引用同一对象表，
  便于后续归档做全局对象重映射）；`PassthroughCheckpoint::dax_pages`
  （排序、唯一、非零 4 KiB 页）；`PassthroughFs::checkpoint_with_dax`；
  `PassthroughFs::map_dax(DaxWindow, &DaxPages)`；
  `Fs::restore_session(.., &DaxPages)` 在激活前把窗口映射到本设备窗口，
  要求窗口存在性和大小与保存一致。状态与页先校验后产生副作用（覆盖、
  对齐、对象范围、`off_t` 上限、页序、页位于匿名映射内且非全零）。
- 捕获只读窗口内存，不读取宿主对象，源 atime 不变。

初版验证（2026-10-24）：amd64 离线容器 `make snapshot-fmt`、
`snapshot-check`（含无 feature 的 `krun-vmm`、`krun-devices`）、
`snapshot-build` 通过；`snapshot_fs` 20/20、`krun-devices` snapshot
103/103。原生 arm64 容器（`SNAPSHOT_TARGET=aarch64-unknown-linux-gnu`）
`snapshot_fs` 20/20，其中 `mseal` 宿主失败用例实际运行；amd64 容器经
Rosetta 运行，`mseal` 返回 ENOSYS，该段跳过。macOS `snapshot-check`
（`krun-devices`）编译通过。九项变异检查中八项被测试捕获；去掉 `msync`
无法从读取观察（共享映射与页缓存一致），属已知测试缺口。clippy 未安装，
未运行。KVM 仍 **UNVERIFIED**。

fail-closed 修正验证（2026-10-24）：原依赖 `mseal` 的失败段（无 `mseal`
时跳过）改为仅测试编译的系统调用边界故障钩子
（`passthrough::dax_faults`，按目标地址触发：`MAP_FIXED` 先 munmap 再
失败、`mprotect` 只改第一页后失败），任何 Linux 主机均实际运行。新增
`snapshot_fs_dax_host_failures_lose_the_window`、
`snapshot_fs_dax_device_freeze_fails_on_a_lost_window`、
`snapshot_fs_restore_session_rejects_pages_without_a_window`。
`make snapshot-fmt` 通过；amd64 容器（容器内先 `touch` 改动文件强制
重新编译）`make snapshot-check` 通过、`snapshot_fs` **23/23**。撤销
`dax.rs`/`device.rs` 生产修正（仅保留钩子与 `DaxLost` 变体作适配）后
3 个新测试失败，恢复后通过。未重跑 arm64、macOS 和全部 krun-devices。

### 批次 2 其余部分：独立对象归档（已审查通过）

`linux/passthrough/archive.rs`（清单、校验）及 `archive/{capture,import,host}.rs`。

- 来源：`Fs::archive_source`（worker 已冻结）给出正在服务的 session、等待
  激活的恢复 session，或对无 session 的设备（从未激活或已 reset）以临时
  `PassthroughFs` 生成 pre-FUSE_INIT session，其中包含 DAX 窗口内容。
  `ShareArchive::capture(Vec<ShareSource>)` 一次捕获 VM 的全部共享。
- 捕获：每个共享通过 `O_PATH`、不跟随符号链接的描述符遍历整棵树（含未
  lookup 对象）；先 statx 再读取；目录与文件通过新的 `O_NOATIME` 描述读取，
  无权限时回退，源 atime 可能变化；读取符号链接目标必然改变该链接的
  atime（归档保存读取前的值）。按宿主 (dev, ino) 跨共享去重，硬链接
  （含跨共享）和共享/嵌套根保持单一对象，目录只有一个父目录。每个共享
  只经自己的根描述符及由此打开的子目录描述符遍历（对象表仍按
  (dev, ino) 去重），因此同一目录的另一个 bind mount 视图按该共享所见
  列出并检查子挂载，再次列出的目录必须一致。
- 扩展属性前置检查：内核仅对初始 user namespace 中具备 CAP_SYS_ADMIN
  的进程列出和读取 `trusted.*`。`ShareArchive::capture` 在读取任何源对象
  之前检查有效 CAP_SYS_ADMIN 且 `/proc/self/ns/user` 为初始 user
  namespace（nsfs inode `0xEFFFFFFD`），否则返回 `Unsupported`，不再
  静默丢失；归档代码本身不提升任何权限。读取 `user.*` 需要对象读权限，
  导入 `trusted.*` 同样需要 CAP_SYS_ADMIN，不满足时显式失败。
- 拒绝：FIFO、socket、设备（char 0:0 whiteout 除外）、mount ID 与根不同的
  子挂载（含同设备 bind mount）、多父目录或环、仍有链接但不在任何共享内的
  session 对象、exported FD（含 handle 释放后仍留在导出表中的项）、已删除
  的共享根；statx 缺少 mount ID 时失败。仅 session 保留的对象（打开或仅被
  DAX 映射的已删除文件、节点持有的已删除目录/符号链接）按孤儿归档。
- 视图：每个共享为其可达的全部对象（含未 lookup 对象）保存 guest inode
  与 ctime；投影后更新 `next_synthetic_ino`。
- 清单 `ArchiveManifest`（对象、顶层树、共享、init 长度）为纯元数据；
  文件内容、去重后的 init.krun、DAX 页为三个独立二进制载荷，按
  files、init、pages 顺序（`write_files` 流式写出并在源文件变化时失败、
  `write_init`、`write_pages`、`lengths`）。
- 导入 `ImportedArchive::import`：先完整校验清单（原始字节名、ID、引用、
  类型、长度、时间戳、拓扑、FUSE options、session 状态、DAX 页偏移）再独占
  创建 0700 目标；全部按目录 FD 创建且不跟随符号链接：共享树为 `0`、`1`…，
  孤儿在临时目录下创建、打开后删除名字（保持 nlink 0），再建硬链接，然后
  按 owner、xattr（删除源中没有的继承 ACL 等）、mode、时间设置元数据，
  最后逐对象比对。每个新名字（含目标目录本身）在创建成功后立即入日志，
  再取得身份：普通文件取自 `O_CREAT|O_EXCL` 返回的描述符（读取前保留在
  日志中供清理使用），硬链接经对象自身描述符的 `/proc/self/fd` 链接创建、
  身份在创建前已知，目录/符号链接/whiteout 创建后立即按名字 statx。
  失败或未 `persist` 即 drop 时，先 retire（批次 3 前为 reset）并 join `hold` 的设备 worker，
  再按日志仅删除本次创建且仍指向原对象的名字（先恢复本进程所有权与
  0700）。他人写入的目录和名字、已存在的目标目录保留；目录/符号链接/
  whiteout 创建后若未能读取身份，该名字可能已被替换，故保守保留（记
  warning，其上级目录随之保留），不按类型/属主/链接数推断归属。
- 恢复：`Fs::restore_imported` 在 `ImportedArchive::root` 上的新设备恢复
  session 与 DAX 窗口；源设备已激活时随后 `activate_frozen`，否则由 guest
  自行激活。`restore_session` 现将存档 init.krun 写入配置，设备 reset 后
  仍提供存档内容。设备 reset 结束其正在服务或等待激活的（恢复）session，
  下次激活重新 FUSE_INIT，并仍提供存档 init.krun；快照共享的 DAX 窗口
  恢复为私有零内存（新 ledger 的前提）。若 session 的窗口已因宿主映射
  失败丢失，reset 不再触碰窗口（其中部分可能已不属于设备）。该情形或
  reset 重映射失败时设备退役：激活失败（早于创建 worker），
  `restore_session`（早于映射）、`archive_source`、`snapshot_session`
  返回 `DaxLost`，owner 须丢弃设备。

验证（2026-10-24，首版）：amd64 离线容器，参数为下文命令加
`--cap-add SYS_ADMIN --tmpfs /tmp:rw,exec`（whiteout、`trusted.*`、bind mount
需要），每次在容器内 `touch` 改动文件。`make snapshot-fmt` 通过；
`snapshot_fs` 35/35；`krun-devices` snapshot 118/118；`snapshot-check`
（含无 feature 的 `krun-vmm`）与 `snapshot-build` 通过；macOS
`snapshot-check`（`krun-devices --features net`）编译通过。KVM 仍
**UNVERIFIED**。

审查修正验证（2026-10-24）：同一容器参数（容器内先 `touch` fs 源文件）。
`make snapshot-fmt`、`make snapshot-check` 通过；`snapshot_fs` **42/42**。
既有行为修正（reset 窗口、reset 后 init、handle 已失效的导出表项）的
回归测试改用 `c79d6ff` 已有接口写在 `fs/tests.rs`：在 `git archive
c79d6ff` 树中（全部非测试文件与 `c79d6ff` 逐字节一致，唯一测试侧适配是
去掉 `mod archive;`）3 个测试失败（读到 `0x33` 文件页、读到默认 ELF
init、`FUSE_DESTROY`+再 INIT 后导出项被接受），当前树通过。四项修正以
修正前的完整归档快照为基线：6 个新测试失败（11 个名字在 reopen/stat
之前失败均遗留目标目录；bind mount 视图被误拒为子挂载；reset 失败后
仍可激活；reset 重映射了已丢失窗口；reset 未结束待激活的恢复 session，
窗口仍为 `0x33`；无 CAP_SYS_ADMIN 时捕获成功、`trusted.*` 被静默丢弃），
其余 36 个通过；基线中仅加入测试编译的故障注入点作适配（导入名字在
reopen 前、目标目录在 statx 前），未含任何修正逻辑。按协调者审查去掉
按类型/属主/链接数推断归属的中间版本上，新增的同类型替换测试失败
（名字 1–9 处换入的外来对象被删除），身份取得前失败的用例清理了全部
名字（应保留 7 个）。修正后全部通过。

已知限制：捕获需初始 user namespace 中的 CAP_SYS_ADMIN（否则拒绝）；
chattr 标志、稀疏文件空洞布局（导入时全零块保留为空洞）、宿主链接计数中
不在共享内的链接不归档；捕获与导入均为每个对象持有一个描述符；DAX 页在
读取载荷后才做数据相关校验（全零页），失败时清理已创建资源。归档批次
记录的 `map_dax` 中途失败未退役设备、非 UTF-8 嵌套根路径（`Fs::new` 取
`String`）两项已在批次 3 处理（见下）。

### 批次 3：owner、v7 格式和最终回归（已审查通过，本地提交）

`src/vmm/src/ram_snapshot/virtio_fs.rs`（owner）及测试
`virtio_fs/{tests,kvm_tests}.rs`；设备侧改动见本节末。

- `RamSnapshotVm::attach_fs(FsShareConfig { tag, source, read_only,
  allow_root_dir_delete, dax: Option<DaxRange { gpa, len }> })`，仅 vCPU
  启动前。共享 i 固定在 MMIO `0xd000d000 + i * 0x1000`、GSI `9 + i`，最多
  七个。tag 1–36 字节、无 NUL、owner 内唯一；源目录为绝对路径、不是指向
  目录的符号链接、除 NUL 外任意字节（含非 UTF-8）。所有检查先于任何
  副作用，之后的失败使 owner 不可再快照（与其他设备一致）。
- DAX 窗口：4 KiB 对齐、非零、不回绕；owner 自行映射私有匿名内存，并在
  RAM 之后注册为额外 KVM memslot，计入目标容量；不是 guest RAM（RAM
  镜像、RAM 别名探测和队列校验只看 `GuestMemoryMmap`，环位于 DAX 窗口时
  拒绝）。统一冲突检查：RAM、全部已挂载设备 MMIO 槽、其他 DAX 窗口，以及
  KVM 自身服务的地址（`KVM_TSS_ADDRESS - 0x1000` 起 16 KiB 的 EPT 恒等映射
  页与 TSS、IOAPIC `0xfec00000`、LAPIC `0xfee00000`），任意挂载顺序均生效
  （后挂载的设备落在窗口上同样拒绝），导入时按元数据做同样检查。owner
  持有其映射的每个窗口（含挂载或导入失败时的窗口）直到自身析构，晚于
  VM fd（及 memslot）关闭。
- RAM 别名探测计入每个共享的映射克隆：transport 1 个，激活后另有设备
  状态与 worker 各 1 个。
- 生命周期：pause 与磁盘、NIC 一起冻结已激活共享的 worker；共享丢失 DAX
  窗口时 pause 失败并禁用 owner。resume 恢复 worker。owner 停止（禁用、
  导入失败、析构）时在 vCPU 停止后对每个共享执行 `Fs::retire`，然后才
  释放窗口。
- `declare_host_writers_stopped()`：仅在运行、可用、未暂停且未退出时接受；
  调用方保证直至下次 resume，宿主上没有写入共享目录及其文件任何别名
  （硬链接、bind mount、打开的描述符）的写者。pause 保留，resume 与禁用
  清除；含共享且未声明的导出在创建镜像前拒绝。导入的副本只属于 owner，
  因此导入后即为已声明。
- 导出：各共享 `Fs::archive_source` 后一次 `ShareArchive::capture`。捕获
  需要初始 user namespace 中的 CAP_SYS_ADMIN（否则 `trusted.*` 不可见），
  缺少时导出以归档的 `Unsupported` 错误失败，owner 保持暂停且可重试。
  JSON 的 `fs` 段含每个设备（槽位、tag、只读与根删除标志、DAX 范围、
  transport 与 virtio 状态及冻结游标）和归档清单（对象、共享根、各
  session 及其 DAX 映射），不含共享的宿主路径或描述符。文件、init.krun、
  DAX 页载荷依次写在磁盘段之后；捕获后有变化的文件使导出失败。
- 完整镜像 **v7**：版本 1–6 显式拒绝（RAM-only `KRUNRAM` 仍为 v1），JSON
  上限 16 MiB 不变。读取时先校验 RAM 区域（其后的设备检查依赖它们），再
  校验各设备段，最后用 RAM、磁盘段、共享载荷长度（均为 checked 加法）
  核对文件总长。
- 导入：`RestoreResources::fs_dir` 当且仅当镜像含共享时提供，须为不含
  NUL 的绝对路径（相对路径会让设备服务、reset 和根删除依赖进程工作目录，
  故拒绝）。RAM 存在前校验清单、各设备固定槽、tag、特性与激活一致性、
  未激活设备不含 FUSE session（无 options、node、handle）、DAX 窗口与
  session 一致、只读共享无可写 handle、可写文件映射或 writeback、窗口
  布局及 memslot 容量；载入 RAM 后、创建任何目录/socket/线程前校验所有
  环。共享在磁盘段之后导入 `fs_dir`（0700 独占创建，已存在则拒绝且不
  触碰，失败只删除本次创建的名字）。每个设备以 `Fs::new_at` 在导入根
  （原生路径）上、按保存的槽位重建，获得新的 DAX 窗口与恢复的 session
  和窗口内容；已激活的共享以冻结 worker 恢复激活，全部早于 vCPU 线程。
  成功后保留导入的树（`persist`）：它是 guest 的文件系统，owner 析构时
  不删除，与磁盘段不同。`allow_root_dir_delete` 删除的是该导入根本身。

设备侧改动（Linux）：`passthrough::Config::root_dir` 改为 `PathBuf`，
`Fs::new_at` 可服务非 UTF-8 根路径；根路径含 NUL 时 FUSE_INIT 返回
`EINVAL`，不再 panic。`Fs::retire` 用于拆除：停止并 join worker、丢弃
session，但从不重映射 DAX 窗口（其所有者随后可能释放该内存；只有 guest
reset 把窗口恢复为零内存）；`Fs` 析构和导入守卫析构改为 retire 而非
reset。退役设备不再激活、恢复或捕获（`Fs::must_discard`）。`map_dax`
中途失败现使窗口丢失并退役设备。每次失败的 `mmap(MAP_FIXED)`（映射请求、
`map_dax` 恢复、reset 重映射即整个窗口）记录其目标窗口范围
（`Fs::dax_unowned`、`PassthroughFs::dax_unowned`）；`mprotect` 失败不会
解除映射，不记录。这类范围可能已被进程内其他内存占用，owner 永不解除
映射，带 warning 保留至进程结束（无法回收）。guest 不会在这类范围上运行：
owner 为每个带窗口的共享设置 `passthrough::DaxMappingControl`
（`Fs::set_dax_control`、`Config::dax_control`），窗口上的每次宿主映射调用
（映射请求、init.krun 复制、移除、`map_dax`、reset 重映射的 `MAP_FIXED`，
以及每次 `mprotect`）都在 `exclusive` 内执行；因执行已结束而被跳过的调用
返回 `EIO` 并使窗口丢失（跳过的 reset 使设备必须丢弃），但它未改变任何
映射，因此不记录 unowned 范围，拆除时仍释放整个窗口。普通共享没有该控制，行为不变（见下文“DAX 执行
屏障修正”）。另导出 `FS_FEATURES`、`FS_NUM_QUEUES`、`FS_QUEUE_SIZE`。

测试：设备侧新增 5 个（其中 4 个只用归档提交已有接口检查既有缺陷：
设备析构与导入守卫析构保持窗口、`map_dax` 失败退役设备、根路径含 NUL；
另 1 个检查 retire 语义与各类失败记录的范围）。owner 的 `snapshot_fs_vmm`
（无 KVM，transport + guest RAM + 与 owner 相同方式映射的 DAX 窗口）7 个：
源目录删除后在副本上继续（中断状态、切点处已发布未处理的请求、原 handle、
可写 DAX 文件映射、1 + 2 个映射克隆）；非 UTF-8 嵌套根在其导入根上恢复，
根删除移除该路径；元数据逐项拒绝且核对拒绝原因；DAX 窗口中的环；tag、
源路径、窗口形状、槽位与 `fs_dir`；窗口后备内存不解除不属于它的范围；
声明要求。`full/tests.rs` 新增经 `read_metadata` 检查 v7 共享段与长度、
RAM 区域先于设备段校验（回归：曾在 legacy CMOS 计算中溢出 panic），并
更新 v1–v6 拒绝和 `fs_dir` 资源要求。`snapshot_fs_kvm` 4 个（仅编译）：
guest 通过 mailbox 以绝对地址访问共享寄存器与 DAX、GSI 9 pending 中断在
恢复后只投递一次、源目录删除后原 handle 与 DAX 映射在副本上继续、CPU
续跑、声明规则、任意顺序的挂载布局、导入 `fs_dir` 契约。`full/guest.S`
另解除 IRQ9 屏蔽并在 0x9126 计数 vector 0x29，`make snapshot-guest`
重建 `guest.bin`（重建旧 `guest.S` 与旧 `guest.bin` 逐字节一致）。

历史验证（屏障修正前的 owner 树，2026-10-24，amd64 `rust:1-bookworm` 离线容器，
`--cap-add SYS_ADMIN --tmpfs /tmp:rw,exec`，无 `/dev/kvm`，容器内先 `touch`
fs 与 ram_snapshot 源文件）：`make snapshot-fmt`、`snapshot-check`（另含
无 feature 的 `krun-vmm`、`krun-devices`）、`snapshot-build`、
`snapshot-guest` 以及 macOS `snapshot-check`（`krun-devices --features net`）
通过。`make snapshot-test`：`krun-devices` snapshot **130/130**（其中
`snapshot_fs` 47）；`krun-vmm` **54 通过、52 失败**，全部失败为打开
`/dev/kvm` 失败（原有 48 个 KVM 测试 + 新增 4 个 `snapshot_fs_kvm`，
**UNVERIFIED**）。无 feature 的 `krun-vmm`：50 通过、39 失败，原因相同。
macOS 原生 console/net/vsock 回归 26/26、20/20、16/16。既有缺陷对照：在
`git archive bb0617d` 树（全部非测试文件逐字节一致；测试侧适配只把根路径
写成 `String` 并去掉新接口断言）中 4 个缺陷测试在各自检查点失败（两处
拆除后窗口读到 0 而非 0x33、`map_dax` 失败后第二次恢复被接受、根路径含
NUL 时 FUSE_INIT panic），其余 42 个通过；当前树全部通过。

BoxLite/shim 生命周期接入留在阶段 13（未来工作）。未授权推送、PR 或部署。

## DAX 执行屏障修正（批次 3，已审查通过）

问题：`MAP_FIXED` 可能先解除旧映射再失败，该范围随后可被进程内其他内存
占用；修正前运行中的 guest 会通过窗口 memslot 继续访问它，直到下一次
pause 才发现。现在该窗口在 guest 运行时不存在。

- 设备侧（`passthrough/dax.rs`）：对象安全的 `DaxMappingControl::exclusive`
  （`Config::dax_control`，`Fs::set_dax_control`）。快照共享窗口上的每次
  宿主映射调用（setup、init.krun 复制及其 `mprotect`、remove、`map_dax`、
  reset）都在其中执行；执行失败记录 lost 与 unowned（`mprotect` 不记录
  范围）；被跳过的调用返回 `EIO`、窗口 lost，但不记录 unowned。
- vmm 侧（`ram_snapshot/execution.rs`）：每个带 DAX 窗口的 owner 一个
  `ExecutionBarrier`。vCPU 只在 `fd.run()` 期间持有 permit，在模拟 IO/MMIO
  之前、EINTR 清 `immediate_exit` 之前释放（guest reset 可在当前 vCPU 线程
  获取屏障）。重映射：阻止新 permit，用 vCPU kick 信号踢出所有持有者（每
  10 ms 重踢），等待全部离开后才执行系统调用；多个重映射串行。失败或
  panic 在重新开放之前把屏障永久标为 failed，写 owner 的 exit eventfd
  （exit watch 停止所有 vCPU）；之后的 pause/resume/export/declare 禁用 owner
  并 join 全部线程。pause 在 worker 冻结后、resume 在设备恢复后（vCPU
  恢复前及返回成功前）再次检查。`stop_threads` 在 join vCPU 前 retire 屏障，
  释放等待中的 vCPU 与重映射。只踢 permit 持有者，持有者在同一锁下注销后
  才离开 ioctl 路径，因此被踢的 pthread ID 不会是已 join 的线程。
- 锁顺序：transport → device → DAX ledger → 屏障锁（叶子锁，持有时不取
  其他锁，也不在重映射期间持有）。无 DAX 窗口的 owner 与普通 VMM 不受
  影响。
- 测试：`snapshot_execution` 4 个（无 KVM，测试线程持 permit 模拟 KVM_RUN）；
  设备侧 2 个（含 fault hook 失败与被跳过调用不记录范围）；
  `snapshot_fs_vmm_live_remapping_needs_the_execution_barrier`；KVM 2 个
  （双 vCPU 重映射期间计数停止且失败后两个 vCPU 结束；设备恢复期间失败
  时 resume 失败且无 vCPU 运行），**仅编译，UNVERIFIED**。
- 验证（2026-10-24，同一离线容器）：fmt 无差异；check（含无 feature）、
  build、macOS `krun-devices` check 通过；`krun-devices` snapshot 132/132
  （`snapshot_fs` 49）；`krun-vmm` 59 通过、54 失败，全部为打开
  `/dev/kvm` 失败（48 个原有 + 6 个 `snapshot_fs_kvm`）；无 feature 55/41
  同因；macOS console/net/vsock 26/26、20/20、16/16。修正前树（非测试文件
  逐字节一致，测试侧适配仅本地声明 trait、无操作安装控制）上 3 个缺陷
  测试在检查点失败，其余 14 个通过。证据与命令：
  `/tmp/phase12-dax-barrier-report.md`。
- 规模：本修正约 440 行生产代码（非注释约 295 行），加上批次 3 原有约
  1360 行；本阶段只做本地提交，将来若建 PR 须拆分或申请例外。

## v7 镜像布局与 owner 限制（最终）

- 布局：16 字节头（`KRUNVM\0\0`、版本 7、JSON 长度），JSON 状态（非空，
  至多 16 MiB），RAM，各磁盘段，然后按归档顺序的三个共享载荷：文件字节、
  去重后的 init.krun 字节、非零 4 KiB DAX 页。`read_metadata` 依次校验
  CPU 与 VM、RAM 区域、各设备段（fs 段返回载荷长度），最后以 checked 加法
  核对头、JSON、RAM、磁盘与共享载荷长度之和恰等于文件长度。版本 1–6 显式
  拒绝，`KRUNRAM` 仍为 v1。
- 能力前置：含共享的导出需要初始 user namespace 中的 CAP_SYS_ADMIN（仅此
  时内核列出 `trusted.*`），否则在读取源之前返回 `Unsupported`，owner 保持
  暂停、可重试；导入 `trusted.*` 同样需要 CAP_SYS_ADMIN。
- 重复导出：同一次 pause 的多次导出得到相同的暂停 guest、RAM 与设备切点，
  但每次重新读取宿主目录树，因此不保证镜像逐字节相同：读取符号链接会改变
  其 atime（无 `O_NOATIME` 权限时读取文件、目录也会），后续导出按读到的值
  记录；首次导出会在活动共享中为 guest 未 lookup 的对象分配 inode 投影。
  不承诺源 atime 不变。
- DAX 所有权失败为致命：窗口上的宿主映射调用失败后不再有 vCPU 运行，下次
  `pause`、`resume`、`export` 或 `declare_host_writers_stopped` 禁用 owner
  并失败；该调用可能已解除映射的范围不解除、不回收，带 warning 保留至进程
  结束。
- 未知身份清理：导入失败只删除能证明由本次创建的名字；创建后未能读取身份
  的目录、符号链接或 whiteout 保留（记 warning，上级目录随之保留）。
- 导入的共享树在成功后保留，owner 不删除（guest 数据）。

## 最终验证与边界

已接受的证据（屏障修正后的最终树，2026-10-24；命令与日志见
`/tmp/phase12-dax-barrier-report.md`，完整 API 见
`/tmp/phase12-owner-report.md`）：

| 检查 | 结果 |
| --- | --- |
| `make snapshot-fmt`（macOS 主机） | 通过，无差异 |
| 容器 `snapshot-check`（另含无 feature 的 `krun-vmm`、`krun-devices`）、`snapshot-build` | 通过 |
| macOS `snapshot-check`（`krun-devices --features net`） | 通过 |
| 容器 `snapshot-test`：`krun-devices` snapshot | **132/132**（`snapshot_fs` 49） |
| 容器 `snapshot-test`：`krun-vmm`（blk,net） | **59 通过、54 失败**，全部在打开 `/dev/kvm` 时失败（原有 48 + 6 个 `snapshot_fs_kvm`） |
| 容器无 feature `krun-vmm` | **55 通过、41 失败**，原因相同 |
| macOS 原生 console / net / vsock | 26/26、20/20、16/16 |

容器为 amd64 `rust:1-bookworm` 离线容器，`--cap-add SYS_ADMIN --tmpfs
/tmp:rw,exec`，未挂载 `/dev/kvm`。打开 KVM 的测试均为失败，既未跳过也
未通过，完整测试命令因此返回失败。**未验证**：KVM 实际运行（6 个
`snapshot_fs_kvm`、所有需要 VM 的 owner 路径、原有 48 个 KVM 测试）、
Linux guest 的 virtiofs/DAX 驱动（fixture 为实模式 mailbox guest）、首次
DAX ledger 之后的 arm64 Linux、clippy，以及任何 BoxLite/shim 恢复（阶段 13）。

## 已知边界与协调记录

- `create/mkdir/symlink/mknod/link` 在创建宿主对象后执行 lookup：node ID
  耗尽时可能留下已创建对象，但不会发出重复/保留 ID。
- 既有 `descriptor_utils` 的 descriptor 内 split 和 `write_from_at` count
  问题尚未修改；当前 FUSE 测试使用 Linux 驱动的回复布局，后续避免扩大范围。
  批次 3 的 owner 测试中观察到：小于回复缓冲区的 READ（5 字节）返回了多于
  请求长度的数据，测试改为整页读取，未修改该代码。
- Orca run：`run_9438a313f694`。批次 1 与修正已完成；批次 2
  `task_d288b3b9b609` / `ctx_af1c26cdb38e` 因用户要求暂停结算为 failed，
  **并非实现或测试失败**。恢复时使用新 Dispatch，不复用已结算的生命周期 ID。
  DAX ledger 已审查并本地提交（`c79d6ff`）；独立归档由
  `task_170725846c10` / `ctx_6f4ca8a68320` 实现，审查修正由
  `task_bbbbe33e568a` / `ctx_bdbf73fe254d` 完成，均已审查并本地提交
  （`bb0617d`）。批次 3（owner、v7）由 `task_9f334338d6c4` /
  `ctx_9453eddecccd` 实现，其 DAX 执行屏障修正由 `task_d2be56a20512` /
  `ctx_4c954b6bca9c` 实现，均已经 Codex 审查通过，并在阶段 12 收尾提交中
  本地提交。
- 原终端仍可供后续使用；`worker-start --terminal` 返回 agent_unconfigured，
  当前已验证可通过 task-create、dispatch --return-preamble 和 terminal send
  投递新任务。遵循 Orca 技能要求重新确认运行态，不盲目重复启动。
