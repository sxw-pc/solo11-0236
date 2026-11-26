# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

无需外部依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。

## WAL 采录、提交前缀与主库租约

主机房掉电后，读写入口只依据**已证提交前缀**和**物理围栏**恢复，而不是“任期更大”。

- `wal_capture`：每张 WAL 页可带前项摘要 `prev_digest`、节点启动代次 `boot`、签收来源 `source` 与客户端确认票 `ticket`（`ack` 仍为确认位）。完全相同的页只作重送；不同内容的同号页**全部保留**作为分叉证据。`wal.prefix` 只串起客户已确认、且由 `prev_digest` 相连的链：未确认的高任期条目（如 B 的 west）记入 `ignored_forks`，绝不顶替已确认内容；两个**都已确认**的不同摘要抢同一位置时 `blocked`，任何任期都不能替它选边。
- `gateway_fence`：记录网关到节点的实际写链路。`gateway.route` 只改路由，不关闭旧链路；`gateway.fence` 只接受物理证据（连接关闭、路由撤回、监听停止等），控制庭写的租约行返回 `not_physical`，链路仍可达。围栏带时间戳，晚于判定时刻的围栏不能解释更早的可达性。
- `leader_lease`：`leader.issue` 仅在候选持有完整已证前缀、同位置摘要无冲突、且除候选外所有写入口已被物理围栏时签发租约；候选自身没有新任期票时只登记为 `candidate`。`leader.fence` 围栏候选租约，`leader.recover` 一次性复核前缀、见证盘佐证、候选补齐与围栏后决定 `promoted` 或保持 `read_only`。
- `consistent_read`：故障期 `read.consistent` 只从同一已证前缀给出端点目录并附带 `view_digest`；只读客户端重试需带上首次 `view_digest`，视图若移动返回 `view_moved` 而不是把请求静默改道。开放写入后读写都绑定同一 `term`，`write.endpoint` 以 `request_id` 去重，重试不会把一条端点变更应用两次。

`fixtures/故障切换.json` 重放演练：A 任期 7 第 21 项确认 east，B 任期 8 第 21 项未确认 west，见证盘 W 保存 east；29 分仅因 B 的网关仍可达 A 而保持只读并继续提供 east，A 在 34 分被物理围栏后 B 于 35 分凭 east 前缀成为新主。`tests/test_failover_prefix.py` 覆盖两种获准处置、只读视图钉扎、精确一次写入与断电重开。
