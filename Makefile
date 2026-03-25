.PHONY: proto

## proto: regenerate Go bindings from proto/gateon/v1/*.proto using buf
proto:
	buf generate
