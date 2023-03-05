(module
  (func (export "main") (result i32)
    (local i32)
    i32.const 6
    local.tee 0
    global.get 0
    i32.add
    local.get 0
    i32.add
  )
  (global i32 (i32.const 30))
)
