#!/usr/bin/perl

use v5.30.0;
use File::Slurp;
use List::Util qw(sum max any);
use DDP multiline => 0;
use feature qw(signatures);
use bytes;
no warnings qw(experimental::signatures);

use constant TNONE => 0x40;
use constant TI32 => 0x7f;
use constant TI64 => 0x7e;
use constant TF32 => 0x7d;
use constant TF64 => 0x7c;

use constant TU32 => -127;

sub TINT($type) { any { $type == $_ } (TI32, TI64) }
sub TFLT($type) { any { $type == $_ } (TF32, TF64) }

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

my ($magic, $version) = unpack('a4 l', take(8));
die "Wrong signature" unless $magic eq "\x00asm";
l "WASM version $version";

my (@TYPE, @FTYPE, @EXPORT, @GLOBALS);
my @abi_param_regs = qw(rdi rsi rdx rcx r8 r9);

sub parse_type_section() {
	my $ntypes = unpack('C', take(1));
	l "Parsing $ntypes type(s)";
	for(my $i = 0; $i < $ntypes; $i++) {
		my $etype = take_bytes(1);
		die "  Unknown entity type $etype" unless $etype == 0x60;
		my @par = take_lparr_byte();
		my @res = take_lparr_byte();
		l "  Function with param(s) [@par] and result(s) [@res]";
		$TYPE[$i] = { par => \@par, res => \@res };
	}
}

sub parse_function_section() {
	l "Parsing function index(es)";
	my @func = take_vec();
	for (0..$#func) {
		l "  Function $_ index $func[$_]";
		$FTYPE[$_] = { typeidx => $func[$_], type => $TYPE[$func[$_]] };
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

my %OPCODE = (
	0x00 => { name => 'unreachable', code => [ 'ud2' ] },
	0x01 => { name => 'nop', code => [ 'nop' ] },
	# 0x0b => { name => 'end' },
	# 0x0f => { name => 'return', code => [ 'pop rax', 'ret' ] },
	0x1a => { name => 'drop', code => [ 'pop rax'] },
	0x20 => { name => 'local.get \0', args => [ TU32 ], code => [ 'push qword [r10-%0]' ] },
	0x21 => { name => 'local.set \0', args => [ TU32 ], code => [ 'pop rax', 'mov [r10-%0], rax' ] },
	0x22 => { name => 'local.tee \0', args => [ TU32 ], code => [
		'mov rax, [rsp]',
		'mov [r10-%0], rax'
	]},
	0x23 => { name => 'global.get \0', args => [ TU32 ], code => [ 'push qword [^0]']},
	0x24 => { name => 'global.set \0', args => [ TU32 ], code => [ 'pop rax', 'mov [^0], rax']},
	0x28 => { name => 'i32.load align=\0 offset=\1', args => [ TU32, TU32 ], code => [
		'pop rsi',
		# 'add rsi, \1',
		'add rsi, memory + \1',
		'movsx rax, dword [rsi]',
		'push rax',
	]},
	0x2c => { name => 'i32.load8_s align=\0 offset=\1', args => [ TU32, TU32 ], code => [
		'pop rsi',
		# 'add rsi, \1',
		'add rsi, memory + \1',
		'movsx rax, byte [rsi]',
		'push rax',
	]},
	0x2d => { name => 'i32.load8_u align=\0 offset=\1', args => [ TU32, TU32 ], code => [
		'pop rsi',
		'add rsi, \1',
		'add rsi, memory',
		'xor rax, rax',
		'mov al, byte [rsi]',
		'push rax',
	]},
	0x41 => { name => 'i32.const \0', args => [ TI32 ], code => [ 'push \0' ] },
	0x46 => { name => 'i32.eq', code => [
		'pop rax',
		'xor [rsp], rax',
		'mov [rsp], dword 1',
		'jz @1',
		'mov [rsp], dword 0',
		'@1',
	]},
	0x49 => { name => 'i32.lt_u', code => [
		'pop rbx',
		'xor rax, rax',
		'cmp rbx, [rsp]',
		'jb @1',
		'or rax, 1',
		'@1',
		'mov [rsp], rax',
	]},
	0x6a => { name => 'i32.add', code => [ 'pop rax', 'add [rsp], rax' ] },
	0x6b => { name => 'i32.sub', code => [ 'pop rax', 'sub [rsp], rax' ] },
);


sub parse_code($findex, $fname, $locals) {
	my $lblgid = 0;
	my $blkid = 0;
	my @frames = ({ type => 'func', rtype => $FTYPE[$findex]{type}{res}[0] });
	say "\tpush rbp";
	say "\tmov rbp, rsp";
	say "\tmov r10, rsp";
	# Function call must obey SysV ABI as exported and imported functions use it to communicate
	# with the outer world
	my $type = $FTYPE[$findex]{type};
	l "Type: " . np($type);
	die "Number of parameters greater than " . scalar(@abi_param_regs) . " is not supported yet" if $type->{par}->@* > @abi_param_regs;

	my @localmap;
	if(my $fullnlocals = $type->{par}->@* + @$locals) {
		say "\tsub rsp, " . ($fullnlocals * 8);

		my @regs = @abi_param_regs;
		for (1..scalar($type->{par}->@*)) {
			my $addr = 8 * $_;
			say "\tmov [r10-$addr], " . shift(@regs);
			$localmap[$_ - 1] = $addr;
		}
	}

	while($CODE) {
		my $op = take_byte();
		if($op == 0x02) { # block
			say "\t;; block";
			unshift @frames, { type => 'block', rtype => take_byte(), id => $blkid++ };
			say "\tpush rbp";
			say "\tmov rbp, rsp";
		} elsif($op == 0x03) { # loop
			say "\t;; loop";
			unshift @frames, { type => 'loop', rtype => take_byte(), id => $blkid++ };
			say "\tpush rbp";
			say "\tmov rbp, rsp";
			say ".${fname}_label_loop_${blkid}_branch_target:";
		} elsif($op == 0x0b) { # end
			say "\t;; end";
			if(@frames) {
				my $frame = shift @frames;
				if($frame->{type} ne 'func') {
					if(TINT($frame->{rtype})) {
						say "\tpop rax";
					}
					if($frame->{type} eq 'block') {
						say ".${fname}_label_block_$frame->{id}_branch_target:";
					}
					say "\tmov rsp, rbp";
					say "\tpop rbp";
					if(TINT($frame->{rtype})) {
						say "\tpush rax";
					}				
				} else {
					if(TINT($frame->{rtype})) {
						say "\tpop rax";
					}
					say "\tmov rsp, rbp";
					say "\tpop rbp";
					say "\tret";
					return;
				}
			}
		} elsif($op == 0x0c) { # br
			my $target = take_num(1);
			say "\t;; br $target";
			my $tframe = $frames[$target];
			if(TINT($tframe->{rtype})) {
				say "\tpop rax";
			}
			# shift @frames;
			while($target-- > 0) {
				say "\tmov rsp, rbp";
				say "\tpop rbp";
				# shift @frames;
			}
			say "\tjmp .${fname}_label_block_$tframe->{id}_branch_target";
		} elsif($op == 0x0d) { # br_if
			my $target = take_num(1);
			say "\t;; br_if $target";
			my $tframe = $frames[$target];
			my $lblid = $lblgid++;
			say "\tpop rax";
			say "\ttest rax, rax";
			say "\tjz .${fname}_label_br_else_$lblid";

			# Same as br
			if(TINT($tframe->{rtype})) {
				say "\tpop rax";
			}
			# shift @frames;
			while($target-- > 0) {
				say "\tmov rsp, rbp";
				say "\tpop rbp";
				# shift @frames;
			}
			say "\tjmp .${fname}_label_block_$tframe->{id}_branch_target";

			say ".${fname}_label_br_else_$lblid:"
		} elsif($op == 0x0f) { # return
			say "\t;; return";
			say "\tpop rax";
			while(@frames) {
				say "\tmov rsp, rbp";
				say "\tpop rbp";
				shift @frames;
			}
			say "\tret";
		} elsif($op == 0x10) { # call
			my $func = take_num(1);
			my $type = $FTYPE[$func]{type};
			my $fname = 'wasm_func_' . ($EXPORT[$func]{name} // $func);
			say "\t;; call $func ($fname): " . np($type->{par}) . " -> " . np($type->{res});
			if($type->{par}->@*) {
				die "Number of parameters greater than " . scalar(@abi_param_regs) . " is not supported yet" if $type->{par}->@* > @abi_param_regs;
				my @regs = @abi_param_regs[0..($type->{par}->@* - 1)];
				say "\tpop " . pop(@regs) while @regs;
			}
			say "\txor rax, rax";
			say "\tpush r10";
			say "\tcall $fname";
			say "\tpop r10";
			if($type->{res}->@*) {
				if(TINT($type->{res}[0])) {
					say "\tpush rax";
				} else {
					die "Unsupported return type $type->{res}[0]";
				}
			}
		} elsif($op == 0x11) { # call_indirect
			my $typeidx = take_num(1);
			my $tableidx = take_num(1);
			my $type = $TYPE[$typeidx];
			say "\t;; call_indirect $tableidx $typeidx: " . np($type->{par}) . " -> " . np($type->{res});
			say "\tpop rax";
			say "\tmov rdi, [wasm_table_$tableidx + rax * 8]";
			if($type->{par}->@*) {
				die "Number of parameters greater than " . scalar(@abi_param_regs) . " is not supported yet" if $type->{par}->@* > @abi_param_regs;
				my @regs = @abi_param_regs[0..($type->{par}->@* - 1)];
				say "\tpop " . pop(@regs) while @regs;
			}
			say "\txor rax, rax";
			say "\tpush r10";
			say "\tcall rdi";
			say "\tpop r10";
			if($type->{res}->@*) {
				if(TINT($type->{res}[0])) {
					say "\tpush rax";
				} else {
					die "Unsupported return type $type->{res}[0]";
				}
			}
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
			say "\t;; $_";
			my $maxlblid = 0;
			for ($opcode->{code}->@*) {
				my $o = $_;
				$o =~ s/\\(\d)/$args[$1]/xg;
				$o =~ s/%(\d+)/($args[$1] + 1) * 8/eg;
				$o =~ s|\^(\d+)|"wasm_global_" . ($GLOBALS[$args[$1]]{name} // $args[$1])|eg;
				$o =~ s/@(\d+)/
					my $lblid = $lblgid + $1;
					$maxlblid = max($lblid, $1);
					".${fname}_label_$lblid";
				/e;
				say (/^@/ ? "$o:" : "\t$o");
			}
			$lblgid += $maxlblid;
		} else {
			die "Unsupported opcode $op";
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
	for(my $i = 0; $i < $nfunc; $i++) {
		my $fname = 'wasm_func_' . ($EXPORT[$i]{name} // $i);
		say "$fname:";
		my $size = take_num();
		my $nlocals = take_num();
		my @locals;
		for (1..$nlocals) {
			my $num = take_num();
			my $type = take_byte();
			push @locals, $type for $num;
		}
		l "  Function with body size $size, local(s) [@locals]";
		parse_code($i, $fname, \@locals);
	}
}

sub parse_imports_section() {
	my $nimport = take_num(1);
	l "Parsing $nimport import(s)";
	for(my $i = 0; $i < $nimport; $i++) {
		my $module = take_name();
		my $name = take_name();
		my $type = take_byte();
		l "  Import $module\::$name: type $type";
		if($type == 0x00) { # Function
			my $typeidx = take_num(1);
			l "    Function of type $typeidx";
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
			if(TINT($_)) {
				push @args, take_num();
			} else {
				die "Unsupported argument type";
			}
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
		my $emit = sub { $init .= "$_[0]\n" };
		while($CODE) {
			my $op = take_byte();
			last if $op == 0x0b;
			parse_opcode($op, $emit);
		}
		my @bytes = take_lparr_byte();
		my $seg = { init => $init, bytes => \@bytes };
		push @DATASEG, $seg;
		l "  Data segment $i: " . np($seg);
	}
}

say <<EOF
section .text
	default rel
	global main
	extern printf

main:
	push rbp
	call init_globals
	call init_data_segments
	call init_tables
	call wasm_func_main
	mov rsi, rax
	mov rdi, fmt
	xor rax, rax
	call printf wrt ..plt
	pop rbp
	xor rax, rax
	ret
EOF
;

while($CODE) {
	my $type = take_byte();
	my $len = take_num(1);
	l "Section type $type, length $len";
	if($type == 1) {
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

say 'init_globals:';

if(@GLOBALS) {
	for my $i (0..$#GLOBALS) {
		my $global = $GLOBALS[$i];
		say $global->{init};
		say "\tpop rax";
		say "\tmov [wasm_global_" . ($global->{name} // $i) . "], rax";
	}
}

say 'init_data_segments:';

if(@DATASEG) {
	for my $i (0..$#DATASEG) {
		my $seg = $DATASEG[$i];
		say $seg->{init};
		say "\tpop rdi";
		say "\tadd rdi, memory";
		say "\tmov rsi, data_segment_$i";
		say "\tmov rcx, " . scalar($seg->{bytes}->@*);
		say "\trep movsb";
	}
}

say "\tret";

say 'init_tables:';

if(@ELEMENTS) {
	for my $i (0..$#ELEMENTS) {
		my $elem = $ELEMENTS[$i];
		if($elem->{type} eq 'funcref') {
			say $elem->{init_offset};
			say "\tpop rax";
			say "\tcld";
			say "\tlea rdi, [wasm_table_$elem->{tableidx} + rax * 8]";
			for my $ref ($elem->{funcref}->@*) {
				say "\tlea rax, [wasm_func_" . ($EXPORT[$ref]{name} // $ref) . ']';
				say "\tstosq";
			}
		}
	}
}

say "\tret";


say <<EOF
section .data
	fmt: db "%d", 10, 0
EOF
;

if(@GLOBALS) {
	say "\talign 16";
	for my $i (0..$#GLOBALS) {
		say "\twasm_global_" . ($GLOBALS[$i]{name} // $i) . ": dq 0";
	}
}

if(@DATASEG) {
	for my $i (0..$#DATASEG) {
		say "\tdata_segment_$i: db " . join(", ", $DATASEG[$i]{bytes}->@*)
	}
}

if(@TABLES) {
	for my $ti (0..$#TABLES) {
		my $table = $TABLES[$ti];
		my $mintable = $table->{min};
		say "\talign 16";
		say "\twasm_table_$ti: times $mintable dq 0"; # FIXME: Only funcref tables are implemented!
	}
}

if($MEM) {
	my $minmem = $MEM->{min} * 65536;
	say "\talign 16";
	say "\tmemory: times $minmem db 0";
	say "\tglobal memory";
}
