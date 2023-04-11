(module
  (func $allgood)
  (func $fuckup
    unreachable
  )
  (func (export "test") (result i32)
    (i64.eq (i64.div_s (i64.const 10) (i64.const 3)) (i64.const 3))
    call_indirect 1

    (i64.eq (i64.div_s (i64.const 10) (i64.const -3)) (i64.const -3))
    call_indirect 1

    (i64.eq (i64.div_s (i64.const -10) (i64.const 3)) (i64.const -3))
    call_indirect 1

    i32.const 42
  )
  (table 2 2 funcref)
  (table 2 2 funcref)
  (elem 0 (i32.const 0) $allgood $fuckup)
  (elem 1 (i32.const 0) $fuckup $allgood)
)
