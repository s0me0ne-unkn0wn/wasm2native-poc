(module
	(func $sub (param i32 i32) (result i32)
		local.get 0
		local.get 1
		i32.sub
	)
	(func (export "test") (result i32)
		i32.const 50
		i32.const 8
		call $sub
	)
)


