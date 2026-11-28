# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

无需外部依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。

## 消息接入、结果与消费组接管

`message_intake`、`message_result`、`offset_checkpoint` 与 `message_recovery`
构成消息运行面。每条消息的归属是完整版本身份：租户、流、分区、位点、生产者序号
与内容摘要；显示用业务键可在别的租户或流里重复，不能当作全局幂等键。父子任务通过
具体版本指针（`parent_ref`）关联，不凭同名业务键猜测。

- 结果行按消息版本落盘；同版本重放复用真实结果，绝不重复执行外部动作（
  `external_actions` 幂等账本）。
- 消费组代次以 `group_leases` 为栅栏：新代次取得分区后，旧代次即使从暂停中恢复，
  写结果、挂网络、推进位点一律被 `stale_generation` 拒绝。
- 位点只覆盖本组已验证的连续结果，且跨分区子任务的父版本未完成时不得越过；
  封存的子任务位点不会被确认。
- `message_recovery.recover_family` 实现两种合同处置：第 30 分钟前收齐实例归属
  证据且资源租期有效，则复用真实创建记录并挂载网络，客户收到可用实例；否则封存
  子任务、保留实例创建原件，发出未完成通知与人工续办单。
- 证据、客户通知、迟到原件均为只追加原件，重启后可逐项核对，后续状态不会覆盖
  客户已经收到的内容。
