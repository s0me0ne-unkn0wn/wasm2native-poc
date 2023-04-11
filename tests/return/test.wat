(module
	(func $get50 (result i32)
		i64.const -8
		i32.const 34
		i32.const 24
		i32.const 26
		i32.add
		return
		unreachable
	)
	(func (export "test") (result i32)
		call $get50
		i32.const 8
		i32.sub
	)
)


