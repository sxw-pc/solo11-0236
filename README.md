# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

多架构镜像发布由 `image_attest`、`image_promote` 与 `release` 三个模块协同：

- `image_attest` 除不可变构建来源包外，登记顶层清单的逐架构展开、子镜像层摘要、扫描结果、构建机授权及追加式撤销。顶层清单签名只覆盖索引本身，不能替任何子镜像背书。
- `image_promote.promote_manifest` 对清单内每个架构分别验证“来源证明 + 层摘要 + 扫描通过 + 授权构建机 + 未撤销”，逐架构写入发布账；未过审的子摘要置 `rejected`，不会因为同标签另一架构合格而放行。旧的 `promote` 临时行为保留。
- `release` 把逐架构目标摘要、每台节点的拉取/运行回执和独立握手探针维持在同一发布批次：节点回执必须带架构、实际拉取的子摘要、启动代次和服务身份；每节点只有一个启动身份，断电重放幂等；探针通过前旧副本不得停用；途中发现签名失效只暂停未签出节点并对已签出节点记召回义务，不回写清单、不抹旧调用。部分发布可把节点留在已验证旧字节上，并通过 `release.gate` 把新特性调用限定到运行受允许摘要的副本。

无需外部依赖。`python3 -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python3 -m cloudctl init --db state.sqlite
python3 -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python3 -m cloudctl image --db state.sqlite --fixture fixtures/多架构发布-image.json
python3 -m cloudctl release --db state.sqlite --fixture fixtures/多架构发布-release.json
python3 -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。
