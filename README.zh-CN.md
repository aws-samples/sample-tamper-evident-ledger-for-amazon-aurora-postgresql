# 基于 Amazon Aurora PostgreSQL 的防篡改账本

本示例为普通的 PostgreSQL 表保存一份可验证的变更历史。每次插入、更新和删除都会追加到历史表，并串进一条 SHA-256 哈希链。每分钟，所有链的最新哈希会用 AWS KMS 非对称密钥签名，写入启用了 Object Lock 合规模式的 Amazon S3 存储桶。之后，审计方只凭公钥就能证明：历史在锚定之后没有被改写、截断或回滚，数据库管理员做的也不例外。

> **Note:** This is sample code, for non-production usage. You should work with your security and
> legal teams to meet your organizational security, regulatory and compliance requirements before
> deployment.
>
> 本示例代码仅供非生产环境使用。部署前请与贵组织的安全和法务团队合作，满足组织的安全、监管和合规要求。

英文版见 [README.md](README.md)。以英文版为准。

**与 AWS 官方 QLDB 替代方案的关系。** AWS Database Blog 在 2024 年 7 月发布了两篇文章：《Replace Amazon QLDB with Amazon Aurora PostgreSQL for audit use cases》和《Migrate an Amazon QLDB Ledger to Amazon Aurora PostgreSQL》（英文页面现在会重定向，AWS 日本博客的译文仍可访问：[替换](https://aws.amazon.com/jp/blogs/news/replace-qldb-with-amazon-aurora-postgresql/)、[迁移](https://aws.amazon.com/jp/blogs/news/amazon-qldb-to-aurora-postgresql/)）。文章给出的组成部分是：用触发器维护审计表（整行以 JSON 存储）、pgAudit 并把日志长期保存在 Amazon CloudWatch Logs、用 Database Activity Streams 作为数据库管理员操作的可信记录并保存到 Amazon S3。本示例实现了这些组成部分，并补上文章留给用户自己解决的一块：把哈希链的链头签名后锚定到数据库之外，让审计方可以用密码学方法验证历史。

## 适用场景

有些数据既要能用 SQL 查询，又要能证明没被改过，比如账户流水、订单、权益记录、参考数据。用触发器写历史表可以记下每次变更，但数据库权限足够的人也能改历史表。只在库内做哈希链也不够：能改一行的管理员，同样能把后面所有哈希重算一遍。

本示例补上缺的那一块：定期把链头签名，写进数据库管理员改不了的存储，审计时拿数据库和这些锚点比对。应用照常使用普通表和标准 SQL。本示例只创建和使用合成数据，请勿导入真实客户数据。

## 工作原理

| 层 | 做什么 | 能发现什么 |
|---|---|---|
| 历史表 | `AFTER` 行触发器为每次变更追加整行（JSONB）、操作人、时间和事务号。历史表拒绝 `UPDATE`、`DELETE`、`TRUNCATE`。 | 应用误操作；应用账号碰不到历史 |
| 哈希链 | 每行历史保存"本行内容 + 上一行哈希"的 SHA-256。 | 没有重算后续哈希的修改 |
| 签名锚点 | Lambda 函数每分钟用 KMS 给所有链的最新 `(序号, 哈希)` 签名，写入 Object Lock 存储桶。只有这个函数的角色能签名和写入。 | 重算整条链、删除记录、从旧快照恢复数据库 |
| 对账 | 每行当前数据必须等于它在历史中的最后一次修订。 | 绕过变更触发器做的修改 |
| DDL 守卫 | 事件触发器回滚以下 DDL：账本自身表（`ledger.history`、`ledger.migration_checkpoint`）上的任何 DDL；改账本表主键、新增、禁用或删除账本触发器、删除账本表、替换账本函数。 | 迁移工具或 schema 属主削弱账本 |

两种写入模式：
- **同步**（`ledger.capture_change`）：事务提交前完成哈希。同一条链的写入在链头行上串行。
- **异步**（`ledger.capture_change_async`）：触发器只追加，锚定函数每分钟调用 `ledger.seal_all` 补算哈希。写入不串行，但封存前的行不受保护。

哈希输入是一个 JSON 数组，字段里出现分隔符、引号或换行都不会混淆。确切格式见 `sql/01_ledger.sql` 的 `ledger.canonical()` 和 `ledger/verify.py`，审计方可以用任何语言重新实现。

## 与官方方案的对应关系

| QLDB 能力 | 官方给出的 Aurora PostgreSQL 做法 | 本示例 |
|---|---|---|
| Journal | pgAudit，日志导出到 CloudWatch Logs 长期保留 | 集群参数组加载 pgAudit（记录 `ddl,role`），`postgresql` 日志导出到保留 10 年的日志组 |
| `history()` | 触发器把变更行以 JSON 写入审计表，用表权限禁止修改 | 触发器把整行以 JSONB 写入 `ledger.history`；应用账号对它没有权限；只追加触发器连 schema 属主也拦住 |
| 防止特权用户改审计数据 | 用 AWS DMS 把审计数据放到独立的审计库 | 改为让改动可被发现：签名锚点存入 S3 Object Lock，由独立验证程序检查。两种做法可以组合：如果还需要隔离存放，可以再把 `ledger.history` 复制到审计库 |
| 管理员操作的可信记录 | Database Activity Streams，用 Amazon Data Firehose 存到 S3 | `01_deploy.py --activity-stream` 开启并归档到 Object Lock 存储桶；`06_activity_report.py` 列出高危语句 |
| Streams | AWS DMS 变更数据捕获 | 未包含；DMS 可直接用于这些表 |
| 密码学校验（digest、proof） | 未涉及 | 哈希链、每分钟 KMS 签名锚点、`04_verify.py` |
| 从 QLDB 迁移数据 | [example-qldb-ledger-migration](https://github.com/aws-samples/example-qldb-ledger-migration) | 先用该示例迁移数据，再在本示例里做基线和检查点（见"从 Amazon QLDB 迁移"） |

## 架构

所有 SQL 都通过 [RDS Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.html) 执行，使用 IAM 授权和 AWS Secrets Manager 中的凭证。集群在私有子网里，安全组没有任何入站规则，脚本也不需要数据库驱动。集群空闲时自动暂停（最小容量 0 ACU），暂停后的第一次请求要等约 15 秒恢复。架构图见英文版。

| 数据库用户 | 权限 | 使用者 |
|---|---|---|
| `app_user` | 读写账本表；不能读或改历史 | 应用（演示中由 02、03 使用） |
| `ledger_sealer` | 只能执行 `seal_all()`、`list_digests()` | 锚定函数 |
| `auditor` | 读历史、链头和检查点；执行 `verify_chain()`、`reconcile()`（仅限已登记的账本表） | 04_verify.py |
| `ledger_owner` | 账本对象的属主，不能登录 | 表结构变更（受 DDL 守卫约束） |
| master 用户 | 全部权限，包括关闭 DDL 守卫 | 数据库管理（演示中扮演 DBA） |

## 告警

两个 CloudWatch 告警（锚定函数出错、5 分钟没有锚定）会通知 SNS 主题 `<栈名>-alarms`。部署时加 `--alarm-email <邮箱>` 即可订阅（需要点确认邮件）。

## 前提条件与快速开始

需要一个可以使用 Aurora PostgreSQL Serverless v2 和 Data API 的 AWS 账号与区域，以及 Python 3.10 或以上版本。所需 IAM 权限见英文版的 [IAM permissions](README.md#iam-permissions)。

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

ARGS="--expected-account 123456789012 --region us-east-1"   # 换成你的账号 ID；在其他账号下脚本拒绝运行
python 01_deploy.py $ARGS        # 约 10 分钟；公钥导出到 results/
python 02_init_ledger.py $ARGS   # 建 schema、DDL 守卫、示例表和示例交易，并做第一次锚定
python 03_tamper_demo.py $ARGS   # 7 个管理员篡改场景及预期的发现方式
python 04_verify.py $ARGS        # 对整个账本执行审计方的三道检查，并检查迁移检查点
# 可选：05_import_checkpoint.py（见"从 Amazon QLDB 迁移"）、06_activity_report.py（见"Database Activity Streams"）
python 99_cleanup.py $ARGS       # 见"清理"
```

`01_deploy.py --anchor-retention-days N` 设置锚点锁定天数（默认 1 天，试用后第二天就能删桶）。生产环境请按记录保留制度设置。

`04_verify.py` 会下载并检查每一个锚点版本。默认每分钟一个，每天约 1,440 个；作者实测约 3,300 个锚点用时 4 到 7 分钟。生产环境可以记录已验证过的锚点，或者抽样加最新锚点验证。保留期过期的锚点，任何有 `s3:DeleteObject` 权限的人都能删除，删除后就不再参与检查。所以选定的保留期，就是历史可被证明已锚定的时长。为了不让锚点被删或缺失掩盖改写，`04_verify.py` 会判定以下链失败：有行但没有任何有效锚点的链；最新锚点早于 `--max-anchor-age-minutes`（默认 60，设为 `0` 关闭此检查）的链。每条链都会报告最新锚点的时间和之后尚未锚定的行数。这个时长要远小于保留期，验证频率也要高于保留期。

要模拟外部审计方：把 `results/` 里的公钥文件、存储桶的读权限和 `auditor` 数据库用户交给对方，运行 `04_verify.py --public-key <文件>`。验证逻辑在 `ledger/verify.py`，不依赖 AWS，也不依赖数据库。

## 篡改场景

`03_tamper_demo.py` 为每个场景单独建一张小表，以 `app_user` 写 9 次变更并锚定，然后以 master 用户篡改，再执行三道检查。

| | 管理员做了什么 | 链自洽 | 锚点比对 | 对账 | 结果 |
|---|---|---|---|---|---|
| A | 直接 `UPDATE` 历史表 | | | | 被只追加触发器拒绝 |
| B | 关闭 DDL 守卫和只追加触发器，改一行历史 | 发现 | 发现 | | 发现 |
| C | 同 B，再重算全部哈希和链头 | 通过 | 发现 | | 只有锚点能发现 |
| D | 删掉最后 3 行历史并回退链头 | 通过 | 发现 | 发现¹ | 发现；链本身看起来完好 |
| E | `SET session_replication_role = replica` 后改余额（变更触发器不触发） | 通过 | 通过 | 发现 | 只有对账能发现 |
| F | 不关 DDL 守卫，直接禁用只追加触发器 | | | | 被 DDL 守卫拒绝 |
| G | 以 `ledger_owner` 改主键字段名 | | | | 被 DDL 守卫拒绝 |

¹ 演示中被删的行恰好是两个账户的最新修订，所以对账也能发现。删的如果是较早的修订，就只有锚点能发现。

C 和 D 说明了只靠库内哈希链为什么不够。锚点比对会和**每一个**签名锚点比较，而不只是最新那个，所以即使后来的锚点已经记录了改写后的状态，改写依然能被发现。从旧快照恢复的数据库也会被这项检查发现：它的链比已锚定的短。

B 到 E 都需要 master 用户。本示例阻止不了 master 用户，只能让改动被发现。生产环境还应记录 master 用户执行的操作（见"安全注意事项"）。

## Database Activity Streams

```bash
python 01_deploy.py $ARGS --activity-stream
# 之后照常运行 02_init_ledger.py、03_tamper_demo.py
python 06_activity_report.py $ARGS    # 从归档中列出高危语句
```

加上 `--activity-stream` 后，栈会额外创建 Activity Streams 的 KMS 密钥、第二个 Object Lock 存储桶和 Firehose 投递角色。脚本随后开启 Activity Streams（异步模式，约 10 到 20 分钟），并创建 Firehose 流，把加密记录原样写入存储桶。Activity Streams 不支持 Aurora Serverless v2，所以集群改用预置实例（默认 `db.r6g.large`，可用 `--instance-class` 修改），空闲时也不再暂停。

`06_activity_report.py` 解密归档记录，列出关闭 DDL 守卫、禁用或绕过触发器、写 `ledger.history`、替换账本函数、重新登记表的语句，以及数据库用户、客户端地址和时间。生产环境还应按官方文章的做法，在 Kinesis 流上用 Lambda 做近实时告警。Activity Streams 由 IAM 控制，数据库用户（包括 master 用户）既不能关闭它，也读不到记录，所以 master 用户改了数据库，归档里的记录依然在。

## 接入自己的表

```sql
SET ROLE ledger_owner;
CREATE TABLE ledger.orders (order_id text PRIMARY KEY, ...);
CREATE TRIGGER orders_ledger AFTER INSERT OR UPDATE OR DELETE ON ledger.orders
  FOR EACH ROW EXECUTE FUNCTION ledger.capture_change('orders');      -- 或 capture_change_async
GRANT SELECT, INSERT, UPDATE, DELETE ON ledger.orders TO app_user;
RESET ROLE;
SELECT ledger_guard.register_table('ledger.orders');                 -- 以 master 用户执行
```

- 每张账本表都要有主键；复合主键记录为 JSON 数组。
- `capture_change('orders', '16')` 按主键把一张表拆成 16 条链，分散写入压力。
- 查一行的修订历史：`SELECT * FROM ledger.history WHERE table_name = 'orders' AND pk = 'O-1' ORDER BY id`。
- **账本表做 DDL 之后**（加删字段、改类型），对账会报告所有现存行，因为 DDL 不触发行触发器。在事务外执行 `CALL ledger.rebaseline_batched('ledger.orders', 1000, 'order_id');` 重新基线，每 1,000 行提交一次。已有数据的表接入账本时，也要做同样的初始基线。
- **改主键**会被 DDL 守卫拦截。经审批后以 master 用户执行：`ALTER EVENT TRIGGER ledger_ddl_guard DISABLE;` → `ALTER TABLE` → `SELECT ledger_guard.register_table(...)` → `ALTER EVENT TRIGGER ledger_ddl_guard ENABLE ALWAYS;` → 重新基线。把这几步写进变更单。

## 从 Amazon QLDB 迁移

1. 用 [example-qldb-ledger-migration](https://github.com/aws-samples/example-qldb-ledger-migration) 迁移数据。它会导出账本，把每个文档的所有修订加载到 Aurora PostgreSQL，并记录最后一个导出区块的 digest，用于校验导出本身。
2. 给每张迁移过来的表挂上变更触发器并登记（见上一节）。
3. 做基线：`CALL ledger.rebaseline_batched('ledger.<表>', 1000, '<主键列>');`。每一行当前数据都会在 `ledger.history` 里有第一条修订。QLDB 的更早修订留在迁移示例的审计表里，由第 1 步的 QLDB digest 和第 4 步的检查点覆盖。如果希望更早的修订也进入哈希链，就按顺序通过触发器加载每个文档的修订：先插入第一版，再把之后的每一版作为更新执行。
4. 记录检查点，把新链和旧账本关联起来，例如 QLDB `GetDigest` 的输出和导出 ID：

   ```bash
   python 05_import_checkpoint.py $ARGS --chain <链 ID> --source-file qldb-final-digest.json
   ```

   检查点表只能追加，每份锚点清单都包含全部检查点，所以之后对检查点或对它之前那段链的任何改动，`04_verify.py` 都会报告。

## 性能说明

以下是作者在 2 vCPU 的 Aurora PostgreSQL 实例上、每个事务写一行时测得的数据，你的结果会不同，请用自己的表结构和事务模型实测。

- 同步链受链头行锁限制，锁持有到提交，大约每秒 150 到 250 个事务；增加并发或换大实例都不能提高。写入多的表请拆成多条链，或改用异步模式。
- 同步链上单个事务最好不超过约一千行：一个事务反复更新同一个链头，单行成本会越来越高。`rebaseline_batched` 按批提交就是这个原因。
- 从系统表读取主键（这样改了主键名也能继续工作），比在代码里写死字段名，同步链写入慢约 10%。

## 费用与清理

加上 `--activity-stream` 时，还要支付全天运行的预置实例、Kinesis Data Streams（由 Activity Streams 创建）、Firehose 和第二个存储桶的费用。

费用包括：集群活跃期间的 Aurora Serverless v2 容量（空闲 5 分钟后暂停，但启用调度时锚定函数每分钟都会唤醒它；保留栈不用时请停用调度）、Aurora 存储和备份、KMS 密钥（月费加请求费）、Lambda 调用、Secrets Manager、S3 存储和请求、CloudWatch Logs。具体见各服务的定价页。

```bash
python 99_cleanup.py $ARGS
```

脚本在做任何改动前会要求输入栈名确认（`--yes` 跳过确认，用于自动化）。它会删除调度、函数和栈（KMS 密钥进入 7 天待删除期），并停止 Activity Streams、删除 Firehose 流。锚点存储桶（以及开启 Activity Streams 时的归档存储桶）**会保留**：合规模式下，在保留期到期之前，包括 root 用户在内谁都删不掉锚点和存储桶。在此之前，存储桶和对象会留在账号里，持续产生 S3 存储费用（默认保留 1 天，费用很少）。到期后执行：

```bash
python 99_cleanup.py $ARGS --empty-anchor-bucket <上一条命令打印的存储桶名>
```
签名密钥删除后，只有 `results/` 里导出的公钥文件能验证已有锚点：**清理前请先备份公钥文件**。`--empty-anchor-bucket` 只处理带本栈标签（`ledger-stack` 或 `aws:cloudformation:stack-name` 等于 `--stack-name`）且开启了 Object Lock 的存储桶，并要求输入桶名确认。

## 安全注意事项

- **还有谁能不被发现地改历史。** 最近一次锚定之后的改动还不受任何锚点保护（默认最长 1 分钟）；异步链的行在封存前不受保护。能修改密钥策略、存储桶策略或锚定函数的人，也能开始写自己的锚点。请把这些资源的 `kms:PutKeyPolicy`、`s3:PutBucketPolicy`、`s3:PutBucketObjectLockConfiguration`、`lambda:UpdateFunctionCode` 和 `iam:PassRole` 限定给少数安全人员，并在 AWS CloudTrail 中监控这些调用。
- **记录 master 用户的操作。** master 用户能关闭 DDL 守卫并改历史（场景 B 到 E）。请使用 `--activity-stream`（见"Database Activity Streams"），让这些操作记录在数据库之外；并把 `rds:StopActivityStream`、Activity Streams 的密钥、Kinesis 流和归档存储桶限定给安全团队。
- **语句里不要带密钥。** Database Activity Streams 会记录语句文本和**绑定参数**，不要把密码作为参数传给数据库。`02_init_ledger.py` 发给 PostgreSQL 的是 SCRAM-SHA-256 校验值（`ledger/scram.py`），不是密码；pgAudit 也会在日志里隐去 `PASSWORD` 子句。
- **备份。** 能恢复快照的人就能把数据库回滚。锚点比对会报告回滚，但也可以考虑用 AWS Backup Vault Lock 防止备份被删除。
- **锚点的强度取决于保留期。** 按记录保留制度选择 Object Lock 保留期。已写入锚点的保留期不能缩短或取消，但有 `s3:PutBucketObjectLockConfiguration` 权限的人可以缩短以后新锚点的默认保留期。锚点过期后可以被删除，验证程序会判定没有近期锚点的链失败（见 `--max-anchor-age-minutes`）。
- **表结构变更。** DDL 守卫拦截 `ledger.history` 和 `ledger.migration_checkpoint` 上的所有 DDL。业务表上的其他 DDL 是允许的，包括会重写行但不触发行级触发器的 `ALTER COLUMN ... TYPE ... USING`；这样改过的行会被对账检查发现。
- **链校验通过证明什么。** 证明历史在锚定之后没有被改，不证明应用写入的内容正确。
- **存储桶访问日志。** 不开启 S3 数据事件时，AWS CloudTrail 不记录对象级调用（`PutObject`、`GetObject`、`DeleteObject`）。本示例既没有开启数据事件，也没有开启 S3 服务器访问日志；生产环境请为锚点存储桶和归档存储桶开启其中一种。
- **凭证。** 本示例把数据库用户密码放在 Secrets Manager 中，没有开启轮换。生产环境请开启轮换，或让应用改用 IAM 数据库认证。
- **加密。** 集群、存储桶和 Secrets Manager 密钥使用 AWS 托管密钥。生产环境如有要求，请改用自行管理的 KMS 密钥（customer managed key）。
- 威胁模型见 [docs/threat-model.md](docs/threat-model.md)（英文），IAM 策略校验结果见 [docs/access-analyzer.md](docs/access-analyzer.md)。

## 限制

- 只覆盖一个账号和一个区域。生产设计通常会把锚点存储桶放在独立的安全账号。
- DDL 守卫开启时，演示表（`demo_*`）不能删除；请直接删除栈。
- `02_init_ledger.py --reset` 会删除账本。之后 S3 中已有的锚点指向不存在的链，`04_verify.py` 会把它们报告为缺失，直到这些锚点过期。
- 从 QLDB 迁移数据使用上面链接的另一个 AWS 示例；本示例负责基线和检查点。
- 未包含基于 Activity Streams 记录的近实时告警（包含归档和报告）。

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest
```

单元测试不需要 AWS 访问，覆盖 SQL 拆分、哈希链、锚点和检查点验证（篡改、改写、截断、回滚、伪造签名和检查点）、按 RFC 7677 测试向量校验的 SCRAM 校验值、Activity Streams 记录解析、Data API 封装、使用桩客户端的锚定函数，以及模板和仓库的静态检查。上面的脚本就是端到端测试。

## 安全

更多信息见 [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications)。

## 许可证

本库使用 MIT-0 许可证，见 [LICENSE](LICENSE) 文件。
