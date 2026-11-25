# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

无需外部依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。
