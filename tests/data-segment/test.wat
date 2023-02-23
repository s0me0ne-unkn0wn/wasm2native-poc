(module
  (func (export "main")
        (result i32)
    i32.const 0
    i32.load8_u
  )
  (memory 1)
  (export "memory" (memory 0))
  (data (i32.const 0) "\2a")
)
