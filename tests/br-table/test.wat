(module
  (func (export "main") (result i32)
    block $b3 (result i32)
      block $b2 (result i32)
        block $b1 (result i32)
          block $b0 (result i32)
            i32.const 1
            i32.const 1
            br_table $b2 $b1 $b3 $b0
          end
          i32.const 2
          i32.add
        end
        i32.const 4
        i32.add
      end
      i32.const 8
      i32.add
    end
    i32.const 29
    i32.add
  )
)
