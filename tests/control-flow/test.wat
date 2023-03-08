(module
  (func $allgood)
  (func $fuckup
    unreachable
  )
  (func (export "main") (result i32)
    (i32.eq (select (i32.const 10) (i32.const 20) (i32.const 0)) (i32.const 20))
    call_indirect 1
    (i32.eq (select (i32.const 10) (i32.const 20) (i32.const 1)) (i32.const 10))
    call_indirect 1

    i32.const 42
  )
  (table 2 2 funcref)
  (table 2 2 funcref)
  (elem 0 (i32.const 0) $allgood $fuckup)
  (elem 1 (i32.const 0) $fuckup $allgood)
)
