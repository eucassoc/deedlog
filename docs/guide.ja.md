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

タイムスタンプは、チェックポイントと、それがまとめている全記録が、その時点で存在したことを証明します。
1回のタイムスタンプがそれ以前のすべてを押さえるので、記録ごとではなくチェックポイントごとに押せば足ります。
過去の時点のタイムスタンプを、あとから取ることはできません。

```sh
dlog timestamp -tsa https://timestamp.sectigo.com -out checkpoint.tsr checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey -timestamp checkpoint.tsr chain.jsonl
```

FreeTSA のように、ルート証明書が OS の証明書ストアにないタイムスタンプ局は、押すときも検証するときも `-tsa-roots` で指定します。

### 無償のタイムスタンプ局と認定タイムスタンプ局

RFC 3161 のタイムスタンプ局ならどれでも使えます。どれを使うかは運用で決めます。
ふだんは、無償のタイムスタンプ局（FreeTSA、DigiCert、Sectigo など）と、連署サーバーの連署（連署した時刻が入っています）で十分です。
無償のタイムスタンプ局を2〜3か所使えば、1か所に頼らずに済みます。

電子帳簿保存法のように法令で認定タイムスタンプが求められる場合や、裁判になる可能性がある場合は、総務大臣認定のタイムスタンプ局も併用します。
認定タイムスタンプは1件ごとに費用がかかるので、間隔をあけて押します。

| | 無償のタイムスタンプ局 | 認定タイムスタンプ局 |
|---|---|---|
| 押す間隔 | チェックポイントごと | 1日1回、または1時間に1回 |
| 年間の件数 | チェックポイントの数 | 365件（1時間ごとなら8,760件） |
| 証明できる時刻の精度 | チェックポイントの間隔 | 1日、または1時間 |

たとえば cron で、1時間ごとと1日ごとに実行します。

```sh
# 1時間ごと：チェックポイント、連署、無償のタイムスタンプ局2か所
cp="cp/$(date -u +%Y%m%dT%H)"
dlog checkpoint -key operator.key chain.jsonl > "$cp"
dlog cosign -key operator.vkey -witness w1.vkey=https://w1.example -out "$cp.cosigned" chain.jsonl "$cp"
dlog timestamp -tsa https://freetsa.org/tsr -tsa-roots freetsa-root.pem -out "$cp.freetsa.tsr" "$cp"
dlog timestamp -tsa https://timestamp.sectigo.com -out "$cp.sectigo.tsr" "$cp"

# 1日ごと：最新のチェックポイントに認定タイムスタンプ
latest=$(ls cp/*T?? | tail -1)
dlog timestamp -tsa "$ACCREDITED_TSA_URL" -tsa-roots accredited-roots.pem -out "$latest.accredited.tsr" "$latest"
```

紛争になりそうだと分かった時点で、すぐに認定タイムスタンプを追加します。その時点までの全記録が固定されます。
ただし、それより前の時刻は、その時々に押したタイムスタンプで示すことになります。

タイムスタンプを検証できるのは、タイムスタンプ局の証明書が有効な間だけです。
何年も保存する記録は、有効期限が切れる前にタイムスタンプの上から押し直す必要があります（PDF の長期署名 PAdES と同じ考え方）。`dlog` はまだこれに対応していません。

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

## 公開される記録から分かること

運営者が宣言するルール（データをどこにどれだけ置くか、どれくらいの間隔で点検するかなど）は、確かめる人がチェーンと照らし合わせるので、最初から公開するものです。
誰でも読めるので、利用者を装って受領証を受け取っても、それ以上のことは分かりません。受領証から分かるのは、持っている本人の出来事だけです。
ルールを公開しても、守りは弱くなりません。システムを守っているのはアクセス制御で、ルールを秘密にしていることではありません。短い保存期間を宣言すれば、そこにあるデータを狙う価値も下がります。

記録にはダイジェストしか入らないので、証拠の中身は分かりません。ただし傾向は分かるので、運営者は次のように抑えます。

| 記録から見えるもの | 分かりうること | 対策 |
|---|---|---|
| 点検の件数 | 件数とその増減 | 宣言したルールの確認に必要なものだけを記録する |
| 定期処理の時刻 | データがいつ移り、いつどこにあるか | 宣言するのは期限だけにし、処理の時刻は固定しない |
| システムや保管場所の名前 | 使っている委託先や製品 | `form-service`、`archive` のような一般名にする |
