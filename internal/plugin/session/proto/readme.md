# 生成proto.pb.go文件

cd internal\plugin\session\proto
protoc -I .  --go_out=../pb --go_opt=paths=source_relative base/*.proto message/*.proto meta/*.proto meta/protocol/*.proto *.proto
