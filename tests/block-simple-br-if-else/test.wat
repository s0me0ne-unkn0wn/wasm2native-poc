(module
	(func (export "test") (result i32)
		block (result i32)
			i32.const 39
			i32.const 40
			i32.const 41
			i32.eq
			br_if 0
			drop
			i32.const 42
		end
		return
	)
)


