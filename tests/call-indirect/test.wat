(module
	(func $fn1 (result i32)
		i32.const 41
	)
	(func $fn2 (result i32)
		i32.const 42
	)
	(func $fn3 (result i32)
		i32.const 43
	)
	(func (export "test") (result i32)
		i32.const 2
		call_indirect (type 0)
	)
	(table 4 4 funcref)
	(elem (i32.const 1) $fn1 $fn2 $fn3)
)


