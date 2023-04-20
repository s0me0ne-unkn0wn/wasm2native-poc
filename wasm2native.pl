#!/usr/bin/perl

use v5.30.0;
use File::Slurp;
use List::Util qw(sum max min any);
use DDP multiline => 0;
use feature qw(signatures);
use bytes;
use Getopt::Long;
no warnings qw(experimental::signatures);

use constant TNONE => 0x40;
use constant TI32 => 0x7f;
use constant TI64 => 0x7e;
use constant TF32 => 0x7d;
use constant TF64 => 0x7c;

use constant TU32 => -127;

sub TINT($type) { any { $type == $_ } (TI32, TI64) }
sub TFLT($type) { any { $type == $_ } (TF32, TF64) }

my $RUNTIME;
GetOptions('runtime=s' => \$RUNTIME);
$RUNTIME = 'test42' unless any { $RUNTIME eq $_ } qw(pvf);

$ARGV[0] or die;

my $CODE = read_file($ARGV[0], { binmode => ':raw' }) or die;
my $code_length = bytes::length($CODE);

sub l { say STDERR @_ }
sub offset { sprintf('%08x:', $code_length - bytes::length($CODE)) }
sub take($len) {
	my $chunk = substr $CODE, 0, $len;
	$CODE = substr $CODE, $len;
	$chunk;
}

my %argtype = (
	0x7f, 'i32',
	0x7e, 'i64',
	0x7d, 'f32',
	0x7c, 'f64',
);

sub arglist {
	my @r;
	push @r, $argtype{$_} while $_ = shift;
	'[ ' . join(', ', @r) . ' ]';
}

my ($magic, $version) = unpack('a4 l', take(8));
die "Wrong signature" unless $magic eq "\x00asm";
l "WASM version $version";

my (@TYPE, @FTYPE, @EXPORT, @GLOBALS, @FIMPORTS);
my @abi_param_regs = qw(rdi rsi rdx rcx r8 r9);

my @EMIT;
sub emit($insn) { push @EMIT, $insn }
sub emitt($insn) { push @EMIT, "\t$insn" }
sub emitl($text) { push @EMIT, grep { $_ } split /\n/, $text }

sub parse_type_section() {
	my $ntypes = unpack('C', take(1));
	l "Parsing $ntypes type(s)";
	for(my $i = 0; $i < $ntypes; $i++) {
		my $etype = take_bytes(1);
		die "  Unknown entity type $etype" unless $etype == 0x60;
		my @par = take_lparr_byte();
		my @res = take_lparr_byte();
		l "  Function with param(s) " . arglist(@par) . " and result(s) " . arglist(@res);
		$TYPE[$i] = { par => \@par, res => \@res };
	}
}

sub parse_function_section() {
	l "Parsing function index(es)";
	my @func = take_vec();
	my $nimports = scalar @FIMPORTS;
	for ($nimports..($#func + $nimports)) {
		l "  Function $_ type index $func[$_ - $nimports]";
		$FTYPE[$_] = { typeidx => $func[$_ - $nimports], type => $TYPE[$func[$_ - $nimports]] };
	}
}

sub parse_exports_section() {
	my $nexp = take_num();
	l "Parsing $nexp export(s)";
	for (1..$nexp) {
		say STDERR offset();
		my $name = take_name();
		my $kind = take_byte();
		my $index = take_num(1);
		l "  Export '$name', of kind $kind, index $index";
		if($kind == 0) {
			$EXPORT[$index] = { name => $name };
		} elsif($kind == 1) {
			l "    STUB table export";
		} elsif($kind == 2) {
			l "    STUB memory export";
		} elsif($kind == 3) {
			l "    Global export [$index]: '$name'";
			$GLOBALS[$index]{name} = $name;
		} else {
			die "Unsupported export kind $kind";
		}
	}
}

sub op_mem_load($ext, $reg, $width) {
	[
		'pop rsi',
		'lea rax, [rel memory]',
		"mov$ext ${reg}ax, $width [rsi + rax + \\1]",
		'push rax',
	]
}

my %op_mem_store_regs = (byte => 'al', word => 'ax', dword => 'eax', qword => 'rax');

sub op_mem_store($width) {
	[
		'pop rax',
		'pop rdi',
		'lea rbx, [rel memory]',
		"mov $width [rdi + rbx + \\1], $op_mem_store_regs{$width}",
	]	
}

sub op_cmp($cond, $reg) {
	[
		'pop rbx',
		'pop rax',
		"cmp ${reg}ax, ${reg}bx",
		"set$cond al",
		'movzx eax, al',
		'push rax',
	]
}

# All the values are kept on stack as 64-bit. All the i32 values are zero-extended before putting them on stack.

my %OPCODE = (
	0x00 => { name => 'unreachable', code => [ 'ud2' ] },
	0x01 => { name => 'nop', code => [ 'nop' ] },
	0x1a => { name => 'drop', code => [ 'add rsp, 8'] },

	# Both rax and rbx, if they were i32 values, were zero-extended when putting them on stack, so omitting
	# zero-extension when pushing the result is safe.
	0x1b => { name => 'select', code => [
		'pop rcx',
		'pop rax',
		'pop rbx',
		'test ecx, ecx',
		'cmovnz rax, rbx',
		'push rax',
	]},

	# All the local and global values were stack values before they were put into memory, so they were
	# zero-extended when were put on stack, so we don't zero-extend them explicitly.
	0x20 => { name => 'local.get \0', args => [ TU32 ], code => [ 'push qword [%0]' ] },
	0x21 => { name => 'local.set \0', args => [ TU32 ], code => [ 'pop rax', 'mov [%0], rax' ] },
	0x22 => { name => 'local.tee \0', args => [ TU32 ], code => [ 'mov rax, [rsp]',	'mov [%0], rax'	]},
	0x23 => { name => 'global.get \0', args => [ TU32 ], code => [ 'push qword [^0]']},
	0x24 => { name => 'global.set \0', args => [ TU32 ], code => [ 'pop rax', 'mov [^0], rax']},

	0x28 => { name => 'i32.load align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('', 'e', 'dword') },
	0x29 => { name => 'i64.load align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('', 'r', 'qword') },
	0x2c => { name => 'i32.load8_s align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('sx', 'e', 'byte') },
	0x2d => { name => 'i32.load8_u align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('zx', 'e', 'byte') },
	0x2f => { name => 'i32.load16_u align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('zx', 'e', 'word') },
	0x31 => { name => 'i64.load8_u align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('zx', 'e', 'byte') }, # Writing to eax zero-extends to rax by itself
	0x35 => { name => 'i64.load32_u align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_load('', 'e', 'dword') },
	0x36 => { name => 'i32.store align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_store('dword') },
	0x37 => { name => 'i64.store align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_store('qword') },
	0x3a => { name => 'i32.store8 align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_store('byte') },
	0x3b => { name => 'i32.store16 align=\0 offset=\1', args => [ TU32, TU32 ], code => op_mem_store('word') },
	0x40 => { name => 'memory.grow \0', args => [ TU32 ], code => [
		'pop rbx',
		'mov rax, [rel mem_alloc_pages]',
		'add rbx, rax',
		'cmp rbx, [rel mem_max_pages]',
		'ja @0',
		'mov [rel mem_alloc_pages], rbx',
		'jmp @1',
		'@0',
		'mov rax, -1',
		'@1',
		'push rax',
	]},
	0x41 => { name => 'i32.const \0', args => [ TI32 ], code => [ 'mov eax, \0', 'push rax' ] },
	0x42 => { name => 'i64.const \0', args => [ TI64 ], code => [ 'mov rax, \0', 'push rax' ] },
	0x45 => { name => 'i32.eqz', code => [
		'pop rax',
		'test eax, eax',
		'sete al',
		'movzx eax, al',
		'push rax',
	]},
	0x46 => { name => 'i32.eq', code => op_cmp('e', 'e') },
	0x47 => { name => 'i32.ne', code => op_cmp('ne', 'e') },
	0x48 => { name => 'i32.lt_s', code => op_cmp('l', 'e') },
	0x49 => { name => 'i32.lt_u', code => op_cmp('b', 'e') },
	0x4a => { name => 'i32.gt_s', code => op_cmp('g', 'e') },
	0x4b => { name => 'i32.gt_u', code => op_cmp('a', 'e') },
	0x4c => { name => 'i32.le_s', code => op_cmp('le', 'e') },
	0x4d => { name => 'i32.le_u', code => op_cmp('be', 'e') },
	0x4f => { name => 'i32.ge_u', code => op_cmp('ae', 'e') },
	0x50 => { name => 'i64.eqz', code => [
		'pop rax',
		'test rax, rax',
		'sete al',
		'movzx eax, al', # It's either 0 or 1 and zero-extends to 64-bit when writing to rax, so no REX.W needed
		'push rax',
	]},
	0x51 => { name => 'i64.eq', code => op_cmp('e', 'r') },
	0x52 => { name => 'i64.ne', code => op_cmp('ne', 'r') },
	0x56 => { name => 'i64.gt_u', code => op_cmp('a', 'r') },
	0x58 => { name => 'i64.le_u', code => op_cmp('be', 'r') },
	0x5a => { name => 'i64.ge_u', code => op_cmp('ae', 'r') },
	0x67 => { name => 'i32.clz', code => [ 'pop rax', 'lzcnt eax, eax', 'push rax' ]},
	0x68 => { name => 'i32.ctz', code => [ 'pop rax', 'tzcnt eax, eax', 'push rax' ]},
	0x6a => { name => 'i32.add', code => [ 'pop rax', 'pop rbx', 'add eax, ebx', 'push rax' ] },
	0x6b => { name => 'i32.sub', code => [ 'pop rbx', 'pop rax', 'sub eax, ebx', 'push rax' ] },
	0x6c => { name => 'i32.mul', code => [ 'pop rax', 'pop rbx', 'imul ebx', 'push rax' ] },
	0x6e => { name => 'i32.div_u', code => [
		'pop rbx',
		'pop rax',
		'cdq',
		'div ebx',
		'push rax',
	]},

	# Logical operations are commutative and values are guaranteed to be zero-extended when put on stack;
	# op(0, 0) is always 0 for and, or and xor, so it is safe to operate on 64-bit values directly
	0x71 => { name => 'i32.and', code => [ 'pop rax', 'and qword [rsp], rax' ] },
	0x72 => { name => 'i32.or', code =>  [ 'pop rax', 'or qword [rsp], rax' ] },
	0x73 => { name => 'i32.xor', code => [ 'pop rax', 'xor qword [rsp], rax' ] },

	0x74 => { name => 'i32.shl', code => [ 'pop rcx', 'pop rax', 'shl eax, cl', 'push rax' ] },
	0x76 => { name => 'i32.shr_u', code => [ 'pop rcx', 'pop rax', 'shr eax, cl', 'push rax' ] },
	0x77 => { name => 'i32.rotl', code => [ 'pop rcx', 'pop rax', 'rol eax, cl', 'push rax' ] },
	0x7c => { name => 'i64.add', code => [ 'pop rax', 'add [rsp], rax' ] },
	0x7e => { name => 'i64.mul', code => [ 'pop rax', 'pop rbx', 'imul rbx', 'push rax' ] },
	0x7f => { name => 'i64.div_s', code => [
		'pop rbx',
		'pop rax',
		'cqo',
		'idiv rbx',
		'push rax',
	]},
	0x80 => { name => 'i64.div_u', code => [
		'pop rbx',
		'pop rax',
		'cqo',
		'div rbx',
		'push rax',
	]},
	0x83 => { name => 'i64.and', code => [ 'pop rax', 'and [rsp], rax' ] },
	0x84 => { name => 'i64.or', code => [ 'pop rax', 'or [rsp], rax' ] },
	0x85 => { name => 'i64.xor', code => [ 'pop rax', 'xor [rsp], rax' ] },
	0x86 => { name => 'i64.shl', code => [ 'pop rcx', 'pop rax', 'shl rax, cl', 'push rax' ] },
	0x89 => { name => 'i64.rotl', code => [ 'pop rcx', 'pop rax', 'rol rax, cl', 'push rax' ] },
	0xa7 => { name => 'i32.wrap_i64', code => [ 'pop rax', 'mov eax, eax', 'push rax' ] },
	0xad => { name => 'i64.extend_i32_u', code => [] }, # It's nop, as i32 value is already zero-extended on stack
);

sub parse_code($findex, $fname, $locals) {
	sub gen_call($type, $dest) {
		# FIXME: It's obviously possible to overwrite the WASM arguments frame with the ABI frame
		# contents before the call and not to spend excessive stack space; it's just KISS for now
		my $nreg_params = min(scalar $type->{par}->@*, scalar @abi_param_regs);
		my $nstack_params = max(0, $type->{par}->@* - @abi_param_regs);
		# [rsp] -> last argument
		emitt 'push r10';
		if($type->{par}->@*) {
			my $argoffset = 8; # [rsp+8] -> last argument
			if($nstack_params) {
				for(1..$nstack_params) {
					emitt "push qword [rsp+$argoffset]"; # [rsp+16] -> last argument; [rsp+24] -> next argument
					$argoffset += 16
				}
			}
			my @regs = @abi_param_regs[0..($nreg_params - 1)];
			while(my $reg = pop @regs) {
				emitt "mov $reg, [rsp+$argoffset]";
				$argoffset += 8;
			}
		}

		emitt 'xor rax, rax';
		emitt "call $dest";

		emitt 'add rsp, ' . ($nstack_params * 8) if $nstack_params; # Discard ABI call frame, if any
		emitt 'pop r10';
		emitt 'add rsp, ' . ($type->{par}->@* * 8) if $type->{par}->@*; # Discard WASM argument frame, if any

		if($type->{res}->@*) {
			if(TINT($type->{res}[0])) {
				emitt 'push rax';
			} else {
				die "Unsupported return type $type->{res}[0]";
			}
		}
	}
	my $lblgid = 0;
	my $blkid = 0;
	my @frames = ({ type => 'func', rtype => $FTYPE[$findex]{type}{res}[0] });
	emitt 'push rbp';
	emitt 'mov rbp, rsp'; # Block frame
	emitt 'mov r10, rsp'; # Function frame
	# Function call must obey SysV ABI as exported and imported functions use it to communicate
	# with the outer world.
	# FIXME: Stack alignment rule is not implemented yet.
	my $type = $FTYPE[$findex]{type};
	l "Type: " . arglist($type->{par}->@*) . ' -> ' . arglist($type->{res}->@*);

	my @localmap;

	my $nreg_params = min(scalar $type->{par}->@*, scalar @abi_param_regs);
	my $nstack_params = max(0, $type->{par}->@* - @abi_param_regs);
	my $nlocals = scalar @$locals;

	my $frame_offset = 8;
	my $caller_offset = 16;
	my $localidx = 0;

	if(my $fullnlocals = $nreg_params + $nstack_params + $nlocals) {
		emitt 'sub rsp, ' . ($fullnlocals * 8);
	}

	# Load register params
	my @regs = @abi_param_regs;
	for (1..$nreg_params) {
		emitt "mov [rbp-$frame_offset], " . shift(@regs);
		$localmap[$localidx++] = "r10-$frame_offset";
		$frame_offset += 8;
	}

	# Load stack params. They could have been left on caller's frame as it doesn't expect them to
	# persist anyway, but that would ruin stack usage determinism across platforms
	for (1..$nstack_params) {
		emitt "mov rax, [rbp+$caller_offset]";
		emitt "mov [rbp-$frame_offset], rax";
		$localmap[$localidx++] = "r10-$frame_offset";
		$frame_offset += 8;
		$caller_offset += 8;
	}

	# Reserve locals
	for (1..$nlocals) {
		$localmap[$localidx++] = "r10-$frame_offset";
		$frame_offset += 8;
	}

	while($CODE) {
		my $op = take_byte();
		if($op == 0x02) { # block
			emitt ';; block';
			unshift @frames, { type => 'block', rtype => take_byte(), id => ++$blkid };
			emitt 'push rbp';
			emitt 'mov rbp, rsp';
		} elsif($op == 0x03) { # loop
			emitt ';; loop';
			unshift @frames, { type => 'loop', rtype => take_byte(), id => ++$blkid };
			emitt 'push rbp';
			emitt 'mov rbp, rsp';
			emit ".${fname}_label_loop_${blkid}_branch_target:";
		} elsif($op == 0x0b) { # end
			emitt ";; end";
			if(@frames) {
				my $frame = shift @frames;
				if($frame->{type} ne 'func') {
					emitt 'pop rax' if TINT($frame->{rtype});
					emit ".${fname}_label_block_$frame->{id}_branch_target:" if $frame->{type} eq 'block';
					emitt 'mov rsp, rbp';
					emitt 'pop rbp';
					emitt 'push rax' if TINT($frame->{rtype});
				} else {
					emitt 'pop rax' if TINT($frame->{rtype});
					emitt 'mov rsp, rbp';
					emitt 'pop rbp';
					emitt 'ret';
					return;
				}
			} else {
				die "No control stack frames";
			}
		} elsif($op == 0x0c) { # br
			my $target = take_num(1);
			emitt ";; br $target";
			my $tframe = $frames[$target];
			emitt 'pop rax' if TINT($tframe->{rtype});
			while($target-- > 0) {
				emitt 'mov rsp, rbp';
				emitt 'pop rbp';
			}
			emitt "jmp .${fname}_label_$tframe->{type}_$tframe->{id}_branch_target";
		} elsif($op == 0x0d) { # br_if
			my $target = take_num(1);
			emitt ";; br_if $target";
			my $tframe = $frames[$target];
			my $lblid = $lblgid++;
			emitt 'pop rax';
			emitt 'test eax, eax';
			emitt "jz .${fname}_label_br_else_$lblid";

			# Same as br
			emitt 'pop rax' if TINT($tframe->{rtype});
			while($target-- > 0) {
				emitt 'mov rsp, rbp';
				emitt 'pop rbp';
			}
			emitt "jmp .${fname}_label_$tframe->{type}_$tframe->{id}_branch_target";

			emit ".${fname}_label_br_else_$lblid:"
		} elsif($op == 0x0e) { # br_table
			my @brtable = take_vec(1);
			my $default_target = take_num(1);
			push @brtable, $default_target;
			my $default_frame = $frames[$default_target];
			emitt ";; br_table " . np(@brtable) . " $default_target";
			my $lblid = $lblgid++;
			emitt 'pop rcx'; # Jump target index
			emitt "mov ebx, $#brtable"; # The last element is the default one
			emitt 'cmp ecx, ebx'; 
			emitt 'cmova ecx, ebx'; # Use default index if overflowed

			emitt 'pop rax' if TINT($default_frame->{rtype});  # All the branch targets share the same type

			emitt "lea rbx, [rel .br_table_$lblid]";
			emitt 'shl ecx, 3';
			emitt 'add rbx, rcx';
			emitt 'jmp [rbx]';

			my $target = max @brtable;
			while($target >= 0) {
				my $bframe = $frames[$target];
				emit ".br_table_${lblid}_exit_$target:";
				for (0..($target - 1)) {
					emitt 'mov rsp, rbp';
					emitt 'pop rbp';
				}
				emitt "jmp .${fname}_label_block_$bframe->{id}_branch_target";
				--$target;
			}

			emit ".br_table_$lblid:";
			for (@brtable) {
				emitt "dq .br_table_${lblid}_exit_$_";
			}
		} elsif($op == 0x0f) { # return
			emitt ';; return';
			emitt 'pop rax' if TINT($type->{res}[0]);
			for(@frames) {
				emitt 'mov rsp, rbp';
				emitt 'pop rbp';
			}
			emitt 'ret';
		} elsif($op == 0x10) { # call
			my $func = take_num(1);
			my $type = $FTYPE[$func]{type};
			my $fname = $func < @FIMPORTS ? $FIMPORTS[$func]{'name'} . ' wrt ..plt' : ($EXPORT[$func]{name} // 'wasm_func_' . $func);
			emitt ";; call $func ($fname): " . arglist($type->{par}->@*) . " -> " . arglist($type->{res}->@*);
			gen_call($type, $fname);
		} elsif($op == 0x11) { # call_indirect
			my $typeidx = take_num(1);
			my $tableidx = take_num(1);
			my $type = $TYPE[$typeidx];
			emitt ";; call_indirect $tableidx $typeidx: " . arglist($type->{par}->@*) . " -> " . arglist($type->{res}->@*);
			emitt 'pop rax';
			emitt "lea rbx, [rel wasm_table_$tableidx]";
			emitt 'mov rbx, [rbx + rax * 8]';
			gen_call($type, 'rbx');
		} elsif(my $opcode = $OPCODE{$op}) {
			my @args;
			if($opcode->{args}) {
				for ($opcode->{args}->@*) {
					if(TINT($_)) {
						push @args, take_num();
					} elsif($_ == TU32) {
						push @args, take_num(1);
					} else {
						die "Unsupported argument type";
					}
				}
			}
			$_ = $opcode->{name};
			s/\\(\d)/$args[$1]/xg;
			emitt ";; $_";
			my $maxlblid = 0;
			for ($opcode->{code}->@*) {
				my $o = $_;
				$o =~ s/\\(\d)/$args[$1]/xg;
				$o =~ s/%(\d+)/$localmap[$args[$1]]/xg;
				$o =~ s|\^(\d+)|($GLOBALS[$args[$1]]{name} // "wasm_global_$args[$1]")|eg;
				$o =~ s/@(\d+)/
					my $lblid = $lblgid + $1;
					$maxlblid = max($lblid, $1);
					".${fname}_label_$lblid";
				/e;
				emit (/^@/ ? "$o:" : "\t$o");
			}
			$lblgid += $maxlblid;
		} else {
			die "Unsupported opcode " . sprintf('0x%02X', $op);
		}
	}
}

sub take_bytes($num) { unpack("C$num", take($num)) }
sub take_byte() { take_bytes(1) }

sub take_num($unsigned = 0) {
	my $res = 0;
	my $shift = 0;
	my $sign;
	my $took = 0;
	while($CODE) {
		my $byte = unpack('C', substr $CODE, $took, 1);
		my $notlast = $byte & 0b10000000;
		$byte &= 0b1111111;
		$res |= $byte << $shift;
		$shift += 7;
		$took++;
		unless($notlast) {
			$sign = $byte & 0b01000000;
			last;
		}
	}
	unless($unsigned) {
		$res |= (~0 << $shift) if $shift < 64 && $sign;
		if($res & 0x8000_0000_0000_0000) {
			$res -= 1;
			$res = -~$res;
		}
	}
	$CODE = substr $CODE, $took;
	$res;
}

sub take_lparr_byte() {
	my $len = take_num(1);
	return () unless $len;
	take_bytes($len);
}

sub take_vec($unsigned = 0) {
	my $len = take_num(1);
	return () unless $len;
	map { take_num($unsigned) } (1..$len);
}

sub take_name() {
	my $len = take_num(1);
	return '' unless $len;
	unpack("A$len", take($len));
}

sub take_limits() {
	my $has_max = take_byte();
	my $min = take_num(1);
	return { min => $min } unless $has_max;
	my $max = take_num(1);
	{ min => $min, max => $max };
}

sub parse_code_section() {
	my $nfunc = take_num(1);
	l "Parsing $nfunc function(s)";
	my $nimports = scalar @FIMPORTS;
	for(my $i = $nimports; $i < $nfunc + $nimports; $i++) {
		my $fname = ($EXPORT[$i]{name} // "wasm_func_$i");
		emit "$fname:";
		my $size = take_num(1);
		my $nlocals = take_num(1);
		my @locals;
		for (1..$nlocals) {
			my $num = take_num(1);
			my $type = take_byte();
			push @locals, $type for (1..$num);
		}
		l "  Function with body size $size, local(s) " . arglist(@locals);
		parse_code($i, $fname, \@locals);
	}
}

sub parse_imports_section() {
	my $nimport = take_num(1);
	l "Parsing $nimport import(s)";
	my $findex = 0;
	for(my $i = 0; $i < $nimport; $i++) {
		my $module = take_name();
		my $name = take_name();
		my $type = take_byte();
		l "  Import $module\::$name: type $type";
		if($type == 0x00) { # Function
			my $typeidx = take_num(1);
			l "    Function of type $typeidx, index $findex";
			$FTYPE[$findex] = { typeidx => $typeidx, type => $TYPE[$typeidx] };
			$FIMPORTS[$findex++] = { typeidx => $typeidx, module => $module, name => $name };
		} elsif($type == 0x01) { # Table
			my $reftype = take_byte();
			my $limits = take_limits();
			my $table = { reftype => $reftype, %$limits };
			l "    Table import " . np($table);
		} elsif($type == 0x02) { # Memory
			my $limits = take_limits();
			l "    Memory import " . np($limits);
		} elsif($type == 0x03) { # Global
			my $valtype = take_byte();
			my $mut = take_byte();
			l "    Global import " . ($mut ? "mut " : "") . " type $valtype";
		} else {
			die "Unsupported import type $type";
		}
	}
}

my @TABLES;

sub parse_table_section() {
	my $ntab = take_num(1);
	l "Parsing $ntab table(s)";
	for(my $i = 0; $i < $ntab; $i++) {
		my $reftype = take_byte();
		my $limits = take_limits();
		my $table = { reftype => $reftype, %$limits };
		l "  Table $i: " . np($table);
		push @TABLES, $table;
	}
}

my $MEM;

sub parse_memory_section() {
	my $nmem = take_num(1);
	l "Parsing $nmem memori(es)";
	for(my $i = 0; $i < $nmem; $i++) {
		my $limits = take_limits();
		l "  Memory $i: " . np($limits);
		$MEM = $limits; # Current spec only allow single memory
	}
}

sub parse_opcode($op, $emit = sub { say @_ }) {
	my $opcode = $OPCODE{$op};
	die "Unsupported opcode $op" unless $opcode;
	my @args;
	if($opcode->{args}) {
		for ($opcode->{args}->@*) {
			die "Unsupported argument type $_" unless TINT($_);
			push @args, take_num();
		}
	}
	$_ = $opcode->{name};
	s/\\(\d)/$args[$1]/xg;
	$emit->("\t;; $_");
	my $maxlblid = 0;
	for ($opcode->{code}->@*) {
		my $o = $_;
		$o =~ s/\\(\d)/$args[$1]/xg;
		$emit->("\t$o");
	}
}

sub parse_globals_section() {
	my $nglob = take_num(1);
	l "Parsing $nglob global(s)";
	for(my $i = 0; $i < $nglob; $i++) {
		my $valtype = take_byte();
		my $mut = take_byte();
		l "  Global $i type " . ($mut ? "mut " : "") . $valtype;
		my $init = '';
		while($CODE) {
			my $op = take_byte();
			last if $op == 0x0b;
			parse_opcode($op, sub { $init .= "$_[0]\n" });
		}
		my $global = { type => $valtype, init => $init };
		die "Global type $valtype is not supported" unless $valtype == TI32;
		push @GLOBALS, $global;
	}
}

my @ELEMENTS;

sub parse_elements_section() {
	my $nelem = take_num(1);
	l "Parsing $nelem element segment(s)";
	for(my $i = 0; $i < $nelem; $i++) {
		my $initial = take_num(1);
		if($initial == 0x00) {
			my $init_offset = '';
			while($CODE) {
				my $op = take_byte();
				last if $op == 0x0b;
				parse_opcode($op, sub { $init_offset .= "$_[0]\n" });
			}
			my @func = take_vec(1);
			my $elem = { type => 'funcref', init_offset => $init_offset, funcref => \@func, tableidx => 0 };
			l "  " . np($elem);
			push @ELEMENTS, $elem;
		} elsif($initial == 0x02) {
			my $tableidx = take_num(1);
			my $init_offset = '';
			while($CODE) {
				my $op = take_byte();
				last if $op == 0x0b;
				parse_opcode($op, sub { $init_offset .= "$_[0]\n" });
			}
			my $kind = take_byte();
			die "Unsupported element kind $kind" unless $kind == 0;
			my @func = take_vec(1);
			my $elem = { type => 'funcref', init_offset => $init_offset, funcref => \@func, tableidx => $tableidx };
			l "  " . np($elem);
			push @ELEMENTS, $elem;
		} else {
			die "Unsupported element segment initial $initial";
		}
	}
}

my @DATASEG;

sub parse_data_section() {
	my $ndata = take_num(1);
	l "Parsing $ndata data segment(s)";
	for(my $i = 0; $i < $ndata; $i++) {
		my $kind = take_num(1);
		die "Data segment kind $kind is not supported" unless $kind == 0;
		my $init = '';
		while($CODE) {
			my $op = take_byte();
			last if $op == 0x0b;
			parse_opcode($op, sub { $init .= "$_[0]\n" });
		}
		my @bytes = take_lparr_byte();
		my $seg = { init => $init, bytes => \@bytes };
		push @DATASEG, $seg;
		l "  Data segment $i: " . np($seg);
	}
}

if($RUNTIME eq 'test42') {
	emitl <<EOF
section .text
	default rel
	global main
	extern printf

main:
	push rbp
	call init_globals
	call init_data_segments
	call init_tables
	call test
	mov rsi, rax
	mov rdi, fmt
	xor rax, rax
	call printf wrt ..plt
	pop rbp
	xor rax, rax
	ret
EOF
;
} elsif($RUNTIME eq 'pvf') {
	emitl <<EOF
section .text
	default rel
	global init_pvf:function
	global validate_block:function
	global __heap_base
	extern ext_logging_log_version_1

init_pvf:
	push rbp
	call init_globals
	call init_data_segments
	call init_tables
	pop rbp
	ret
EOF
;
}

while($CODE) {
	my $type = take_byte();
	my $len = take_num(1);
	l "Section type $type, length $len";
	if($type == 0) {
		l "  Ignoring custom section";
		take($len);
	} elsif($type == 1) {
		parse_type_section();
	} elsif($type == 2) {
		parse_imports_section();
	} elsif($type == 3) {
		parse_function_section();
	} elsif($type == 4) {
		parse_table_section();
	} elsif($type == 5) {
		parse_memory_section();
	} elsif($type == 6) {
		parse_globals_section();
	} elsif($type == 7) {
		parse_exports_section();
	} elsif($type == 9) {
		parse_elements_section();
	} elsif($type == 10) {
		parse_code_section();
	} elsif($type == 11) {
		parse_data_section();
	} else {
		die "Unsupported section type $type";
	}
}

emit 'init_globals:';

if(@GLOBALS) {
	for my $i (0..$#GLOBALS) {
		my $global = $GLOBALS[$i];
		emit $global->{init};
		emitt 'pop rax';
		emitt "mov [" . ($global->{name} // "wasm_global_$i") . "], rax";
	}
}

emitt 'ret';

emit 'init_data_segments:';

if(@DATASEG) {
	# $need_got = 1;
	for my $i (0..$#DATASEG) {
		my $seg = $DATASEG[$i];
		emitl $seg->{init};
		emitt 'pop rdi';
		emitt 'lea rax, [rel memory]';
		emitt 'add rdi, rax';
		emitt "mov rsi, data_segment_$i";
		emitt "mov rcx, " . scalar($seg->{bytes}->@*);
		emitt 'cld';
		emitt 'rep movsb';
	}
}

emitt 'ret';

emit 'init_tables:';

if(@ELEMENTS) {
	# $need_got = 1;
	for my $i (0..$#ELEMENTS) {
		my $elem = $ELEMENTS[$i];
		if($elem->{type} eq 'funcref') {
			emitl $elem->{init_offset};
			emitt 'pop rax';
			emitt 'cld';
			emitt "lea rbx, [rel wasm_table_$elem->{tableidx}]";
			emitt 'lea rdi, [rbx + rax * 8]';
			for my $ref ($elem->{funcref}->@*) {
				emitt "lea rax, [" . ($EXPORT[$ref]{name} // "wasm_func_$ref") . ']';
				emitt 'stosq';
			}
		}
	}
}

emitt 'ret';

emit 'section .data';

if($RUNTIME eq 'test42') {
	emit 'fmt: db "%d", 10, 0';
}

if(@GLOBALS) {
	emitt 'align 16';
	for my $i (0..$#GLOBALS) {
		emit (($GLOBALS[$i]{name} // "wasm_global_$i") . ": dq 0");
	}
}

if(@DATASEG) {
	for my $i (0..$#DATASEG) {
		emit "data_segment_$i: db " . join(", ", $DATASEG[$i]{bytes}->@*)
	}
}

if(@TABLES) {
	my $has_table = 1;
	for my $ti (0..$#TABLES) {
		my $table = $TABLES[$ti];
		my $mintable = $table->{min};
		emitt 'align 16';
		emit "wasm_table_$ti: times $mintable dq 0"; # FIXME: Only funcref tables are implemented!
		emitt "global wasm_table_$ti";
	}
}

if($MEM) {
	my $minmem = $MEM->{min} << 16;
	my $maxpages = $MEM->{max} // ($MEM->{min} + 128);
	my $maxmem = $maxpages << 16;

	emitt 'align 16';
	emitt "mem_alloc_pages: dq $MEM->{min}";
	emitt "mem_max_pages: dq $maxpages";

	emitt 'align 16';
	emitt "memory: times $maxmem db 0";
	emitt 'global memory';
}

say $_ for @EMIT;
