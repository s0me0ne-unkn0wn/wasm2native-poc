(module
	(func $calc (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
		local.get 0
		local.get 1
		i32.add
		local.get 2
		i32.sub
		local.get 3
		i32.add
		local.get 4
		i32.sub
		local.get 5
		i32.add
		local.get 6
		i32.sub
		local.get 7
		i32.add
	)
	(func (export "test") (result i32)
		i32.const 1
		i32.const 2
		i32.const 3
		i32.const 4
		i32.const 5
		i32.const 6
		i32.const 7
		i32.const 44
		call $calc
	)
)


