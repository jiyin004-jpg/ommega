# B 端模块更新日志

[English](CHANGELOG-B.en.md)

## 1.7.14

- 随 A 端同版本发布，无功能性改动。
- 运行期不再往 /data/local/tmp 写文件：sepolicy 应用日志改到自己的 logs，live 改法所需的 spl_daemon 也不再拷副本到那里。
- 工程模式的「Attestation 全量功能测试」现在能通过。
