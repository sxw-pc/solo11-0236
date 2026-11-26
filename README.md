# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

`billing_facts` 离线保存计费三段原件（原始请求 `billing.capture_request`、代理转发 `billing.capture_proxy`、后端完成 `billing.capture_backend`），每页保留设备、整页摘要、整页共同时钟偏差和入库时间，每行保留代理实例、请求令牌、证书代次、后端回执与物理链路计数器。`request_attribution` 按请求令牌区分物理传输次数与业务执行次数，归属只能由独立证书绑定证据确定；`customer_billing` 独立签发客户账单（追收/冲回只追加不覆盖），`vendor_settlement` 按物理传输量（含重试）向云商付款，并把身份不明的客户责任留在平台账。

无需外部依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。
