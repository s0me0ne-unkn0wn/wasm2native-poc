(module
  (func (export "test")
        (result i32)
	(local i32)
	(local.set 0 (i32.const 2))
	block
	    (i32.ne (i32.const 1) (memory.grow (i32.const 2)))
	    br_if 0
	    (local.set 0 (i32.add (local.get 0) (i32.const 20)))
	end
	block
	    (i32.ne (i32.const -1) (memory.grow (i32.const 1)))
	    br_if 0
	    (local.set 0 (i32.add (local.get 0) (i32.const 20)))
	end
	local.get 0
  )
  (memory 1 3)
  (export "memory" (memory 0))
)
