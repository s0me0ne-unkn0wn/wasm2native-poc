(module
  (func $allgood)
  (func $fuckup
    unreachable
  )
  (func (export "main") (result i32)
    (i32.eq (i32.shr_u (i32.const -1) (i32.const 4)) (i32.const 268435455))
    call_indirect 1
    (i32.eq (i32.shl (i32.const -1) (i32.const 1)) (i32.const -2))
    call_indirect 1

    i32.const 42
  )
  (table 2 2 funcref)
  (table 2 2 funcref)
  (elem 0 (i32.const 0) $allgood $fuckup)
  (elem 1 (i32.const 0) $fuckup $allgood)
)
