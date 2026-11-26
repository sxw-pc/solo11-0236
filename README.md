# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

无需外部依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。

## 可复核检查点与封存

每次成功的签发、撤销、副本持证变更、根包发布或撤回，都在同一事务内追加所属主体的下一条检查点（`checkpoints` 表）。检查点按主体独立编号，仅接续已提交前驱，前驱摘要写入 `prev_digest`，自身摘要覆盖主体、编号、类型、引用、证据与前驱摘要；同号重试读回原记录，冲突内容抛 `CheckpointConflict`，绝不覆盖。事件与检查点以 `event_seq` 双向绑定，`trust.verify` 重算每条链并交叉核对，可发现缺检查点、断链、摘要篡改、同号分叉与孤立检查点。

- `trust.seal`（全局封存）：记录本次实际覆盖的各主体链头编号和全部根包快照（根、状态、窗口、链头），封存摘要一并入 `seals`。链不可验证时拒绝封存，主体集合无法冒充编号覆盖；两次封存之间不同的操作次序留下不同的链头历史。
- 撤销屏障：旧代证书的撤销不能跨过本身份未封存的新代签发现场，命中时返回 `unsealed_issuance_block` 并保留原证书状态、点名阻断前驱。
- 撤包双依据：`trust.withdraw` 只在两类实质证据之一下放行——封存链（`sealed_chain`，引用封存编号与根快照，封存未覆盖最新签发时不可用）或另一活跃根包上的同代实收回执（`live_receipt`，仅“已发布”不能顶替）。依据写入 `migrations`，旧事件与旧代收件（`receipts` 按 包/副本/代次 留存，不再被新行覆盖）保持可追溯；对已撤包的 `trust.retry` 按所留依据给出 `sealed_migration` / `historical_receipt` 结论。
- 分叉隔离：任何主体出现已提交事件缺检查点、前驱断链或同号分叉、或封存被篡改时，签发、撤销、副本变更、发布、确认、覆盖、重试、撤包与握手均返回 `quarantined`，不会因为收件行恰好还在表中而继续放行。

