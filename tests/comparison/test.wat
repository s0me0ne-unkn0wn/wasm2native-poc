(module
  (func $allgood)
  (func $fuckup
    unreachable
  )
  (func (export "test") (result i32)
    (i32.lt_u (i32.const 10) (i32.const 20))
    call_indirect 1

    (i32.lt_u (i32.const 10) (i32.const 10))
    call_indirect 0

    (i32.lt_u (i32.const 20) (i32.const 10))
    call_indirect 0

    (i32.lt_s (i32.const 1) (i32.const 10))
    call_indirect 1

    (i32.lt_s (i32.const 10) (i32.const 10))
    call_indirect 0

    (i32.lt_s (i32.const 20) (i32.const 10))
    call_indirect 0

    (i32.lt_s (i32.const -10) (i32.const 10))
    call_indirect 1

    (i32.lt_s (i32.const 10) (i32.const -10))
    call_indirect 0

    (i32.ge_u (i32.const 10) (i32.const 1))
    call_indirect 1

    (i32.ge_u (i32.const 10) (i32.const 10))
    call_indirect 1

    (i32.ge_u (i32.const 10) (i32.const 20))
    call_indirect 0

    (i32.ge_u (i32.const 10) (i32.const -10))
    call_indirect 0

    (i32.eqz (i32.const 0))
    call_indirect 1

    (i32.eqz (i32.const 10))
    call_indirect 0

    (i32.eq (i32.const 10) (i32.const 10))
    call_indirect 1

    (i32.eq (i32.const 10) (i32.const 20))
    call_indirect 0

    (i32.ne (i32.const 10) (i32.const 10))
    call_indirect 0

    (i32.ne (i32.const 10) (i32.const 20))
    call_indirect 1

    i32.const 42
  )
  (table 2 2 funcref)
  (table 2 2 funcref)
  (elem 0 (i32.const 0) $allgood $fuckup)
  (elem 1 (i32.const 0) $fuckup $allgood)
)
