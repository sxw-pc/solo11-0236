# 服务信任轮替控制庭

离线模拟私有云服务身份与信任根轮替。`identity` 管理身份、证书及副本；`trust` 管理信任包、确认和撤回；`handshake` 管理调用授权、准入和到期风险。SQLite 保留业务状态与事件证据；模拟证书只含身份、代次、根和有效窗，不依赖实际密钥。

无需外部依赖。`python -c "import cloudctl; print(cloudctl.__file__)"` 检查模块来源。

```sh
python -m cloudctl init --db state.sqlite
python -m cloudctl demo --db state.sqlite --fixture fixtures/demo.json
python -m unittest discover -s tests -v
```

各子系统 `fixtures` 下有正常和失败输入。删除演示数据库可重放；测试用临时数据库。

## 硬件召回与保修交割

`cloudctl/hardware_custody.py` 以实体序列号（而不是机箱标签或逻辑副本号）为主键，保存召回公告、铭牌、开封、移装、硬件挑战、封袋重量、运输链、隔离、销毁和恢复证据。`cloudctl/vendor_rma.py` 保存唯一索赔、追加式更正、供应商收件/拒收、拆解、信用确认、采购入库和结算匹配。

常用动作包括 `hardware.announce`、`hardware.confirm_recall`、`hardware.move`、`hardware.asset`、`hardware.challenge`、`hardware.quarantine`、`hardware.bag`、`hardware.destroy`、`service.restore`、`rma.submit`、`vendor.receive`、`vendor.disassemble`、`finance.confirm_credit`、`purchase.receive` 和 `rma.settle`。序列号重复扫描不会产生第二块模块或第二张索赔；现场销毁与整机返厂要求不同的收件和拆解证据，不能互相冒充。

验收硬件召回流水：

```sh
python -B -m unittest tests.test_hardware_rma -v
```
