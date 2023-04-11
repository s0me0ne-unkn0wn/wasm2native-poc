(module
  (func (export "test")
        (result i32)
    i32.const 0
    i32.load8_s
    i32.const 1
    i32.load
    i32.add
  )
  (memory 1)
  (export "memory" (memory 0))
  (data (i32.const 0) "\d6\54\00\00\00")
)
