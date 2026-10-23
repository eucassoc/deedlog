# ガイド

[English](guide.md)

## チェックポイント

チェーン ID はチェックポイントの origin です。運営者が管理するドメイン配下の、スキームなしの URL を使います。
運営者の鍵の名前は origin と同じにします。

```sh
dlog keygen -name city.example/cameras -out operator   # operator.key（秘密）と operator.vkey（公開）
dlog checkpoint -key operator.key chain.jsonl > checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey chain.jsonl
```

チェックポイントの後にチェーンが伸びていても、検証は通ります。

## 連署サーバー

連署サーバー（英語では witness）は、履歴が書き換えられていないことを機械的に確かめ、チェックポイントに連署するサーバーです。
記録の中身は見ません。独立した連署サーバーが連署することで、運営者は相手によって違う履歴を見せられなくなります。
deedlog は C2SP の witness プロトコルに準拠しているので、公開の witness ネットワーク（witness-network.org）を含め、
C2SP に対応した連署サーバーならどれでも使えます。

```sh
dlog cosign -key operator.vkey -witness w1.vkey=https://w1.example -out checkpoint.cosigned chain.jsonl checkpoint
dlog verify -checkpoint checkpoint.cosigned -key operator.vkey -witness w1.vkey -quorum 1 chain.jsonl
```

誰でも、関心のあるチェーンの連署サーバーを運用できます。

```sh
dlog keygen -witness -name witness.city.example -out witness
dlog witness -key witness.key -log operator.vkey -state witness.state -listen :8080
```

## タイムスタンプ

```sh
dlog timestamp -tsa https://timestamp.sectigo.com -out checkpoint.tsr checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey -timestamp checkpoint.tsr chain.jsonl
```

法的な証拠力が必要な場合は、総務大臣認定のタイムスタンプ局を使い、そのルート証明書を `-tsa-roots` で指定します。

## 不正の証明

運営者が履歴を書き換えると、古いチェックポイントを持っている人は誰でも、運営者の公開鍵だけでそれを証明できます。

```sh
dlog misbehavior build -key operator.vkey old.jsonl old-checkpoint new.jsonl new-checkpoint > proof.json
dlog misbehavior check -key operator.vkey proof.json
```

## 受領証

受領証は「この出来事はチェーンの何番に記録した」という運営者の署名付きの約束です。
後で連署サーバーが連署したチェックポイントのその番号に別のものが入っていれば、受領証とチェックポイントを並べるだけで証明できます。

約束（中身）は常に同じ署名付きノートで、運営者の鍵だけで確かめられます。受け取る相手によって変わるのは封筒だけです。

| 受け取る相手 | 封筒 |
|---|---|
| 人 | 検証ページへのリンク（QR コード、メール、ダウンロード）。ウォレットが使える場合は SD-JWT VC |
| データスペースのコネクタ | プロトコルのメッセージに添付 |
| x402 で支払う AI エージェント | HTTP の応答ヘッダー |
| デバイス | 応答の小さなフィールド |

受領証は運営者の手の届かない場所に置く必要があります。本人が保管するか、本人が選んだ場合に、照合してくれる団体に預けます。

```sh
dlog keygen -name city.example/cameras/receipts -out receipts      # チェックポイントとは別の鍵
dlog receipt issue -key receipts.key -index 123 -url "https://verify.example/?lang=ja" chain.jsonl
dlog serve -chain chain.jsonl -checkpoint checkpoint.cosigned       # 最新のチェックポイントと証明を公開

dlog prove -index 123 -leaf chain.jsonl > proof
dlog receipt check -receipt receipt -receipt-key receipts.vkey \
                   -checkpoint checkpoint -key operator.vkey -proof proof -out misbehavior.json
# 終了コード 0：記録されている／3：まだ含まれていない／4：約束違反（不正の証明を出力）
```

受領証のリンクは、[検証ページ](../web/)でブラウザの中だけで確かめられます。検証ページは運営者以外が提供します。
