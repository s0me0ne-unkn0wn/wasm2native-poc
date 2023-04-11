(module
  (func (export "test")
        (result i32)
    i32.const 0
    i32.const 0xAABBCC2A
    i32.store8
    i32.const 0
    i32.load8_u
  )
  (memory 1)
  (export "memory" (memory 0))
)
