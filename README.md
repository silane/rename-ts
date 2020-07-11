# rename-ts
EDCBでデフォルトファイル名で録画したTSファイルの名前をチャンネル情報が入ったものに変える

## 用途
EDCBを何も考えずに使ってTSファイルを録り溜めていたが、mp4などに変換したくなった。しかし、変換するとチャンネル情報がファイル名にもファイルの中身にも残らない。そんなときに使う用。

## 使い方
```sh
python3 rename_ts.py FILE...
```
ファイル名が以下のEDCBのデフォルト形式外のものはスルーされる。

## EDCBのデフォルトファイル名の形式
```
YYYYMMDDhhmmtttttt-[番組名].ts

YYYYMMDD: 日付
hhmm: 時刻
tttttt: チューナを表す6桁の数字
```

## 変更後のファイル名の形式
```
YYYYMMDDThhmmss-nnnnneeeee-[番組名].m2ts

YYYYMMDD: 日付
hhmmss: 時刻
nnnnn: 10進数ネットワークID
eeeee: 10進数サービスID
```

## 詳細
- 日付、時刻、番組名は元のファイル名から取る。秒はないので0固定。
- ネットワークID、サービスIDはファイルの中身を解析して取ってくる。
- 拡張子を m2ts に変えるのは Google Photos にアップロードしやすくするため。ts では拒否される。
