#!/usr/bin/perl

use v5.30.0;
use File::Slurp;
use List::Util qw(sum max any);
use DDP;
use feature qw(signatures);
no warnings qw(experimental::signatures);

use constant TNONE => 0x40;
use constant TI32 => 0x7f;
use constant TI64 => 0x7e;
use constant TF32 => 0x7d;
use constant TF64 => 0x7c;

sub TINT($type) { any { $type == $_ } (TI32, TI64) }
sub TFLT($type) { any { $type == $_ } (TF32, TF64) }

$ARGV[0] or die;

my $CODE = read_file($ARGV[0], { binmode => ':raw' }) or die;

sub l { say STDERR @_ }
sub take($len) {
	my $chunk = substr $CODE, 0, $len;
	$CODE = substr $CODE, $len;
	$chunk;
}

my ($magic, $version) = unpack('a4 l', take(8));
die "Wrong signature" unless $magic eq "\x00asm";
l "WASM version $version";

my (@TYPE, @FTYPE, @EXPORT);

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
		my $name = take_name();
		my $kind = take_byte();
		my $index = take_num();
		l "  Export '$name', of kind $kind, index $index";
		if($kind == 0) {
			$EXPORT[$index] = { name => $name };
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
	0x41 => { name => 'i32.const \0', args => [ TI32 ], code => [ 'push \0' ] },
	0x46 => { name => 'i32.eq', code => [
		'pop rax',
		'xor [rsp], rax',
		'mov [rsp], dword 1',
		'jz @1',
		'mov [rsp], dword 0',
		'@1',
	]},
	0x6a => { name => 'i32.add', code => [ 'pop rax', 'add [rsp], rax' ] },
	0x6b => { name => 'i32.sub', code => [ 'pop rax', 'sub [rsp], rax' ] },
);


sub parse_code($fname) {
	my $lblgid = 0;
	my $blkid = 0;
	my @frames = ({ type => 'func' });
	say 'push rbp';
	say 'mov rbp, rsp';

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
				}
			}
		} elsif($op == 0x0c) { # br
			my $target = take_num();
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
			my $target = take_num();
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
			say "\t;;return";
			say "\tpop rax";
			while(@frames) {
				say "\tmov rsp, rbp";
				say "\tpop rbp";
				shift @frames;
			}
			say "\tret";
		} elsif(my $opcode = $OPCODE{$op}) {
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
			say "\t;; $_";
			my $maxlblid = 0;
			for ($opcode->{code}->@*) {
				my $o = $_;
				$o =~ s/\\(\d)/$args[$1]/xg;
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

sub leb128($bytes, $pc) {
	my $res = 0;
	my $shift = 0;
	my $sign;
	while($bytes->@*) {
		my $byte = $bytes->[$$pc++];
		my $notlast = $byte & 0b10000000;
		$sign //= $byte & 0b01000000;
		$byte &= 0b1111111;
		$res |= $byte << $shift;
		$shift += 7;
		last unless $notlast;
	}
	$res |= (~0 << $shift) if $shift < 64 && $sign;
	if($res & 0x8000_0000_0000_0000) {
		$res -= 1;
		$res = -~$res;
	}
	$res;
}

sub take_bytes($num) { unpack("C$num", take($num)) }
sub take_byte() { take_bytes(1) }

sub take_num() {
	my $res = 0;
	my $shift = 0;
	my $sign;
	my $took = 0;
	while($CODE) {
		my $byte = unpack('C', substr $CODE, $took, 1);
		my $notlast = $byte & 0b10000000;
		$sign //= $byte & 0b01000000;
		$byte &= 0b1111111;
		$res |= $byte << $shift;
		$shift += 7;
		$took++;
		last unless $notlast;
	}
	$res |= (~0 << $shift) if $shift < 64 && $sign;
	if($res & 0x8000_0000_0000_0000) {
		$res -= 1;
		$res = -~$res;
	}
	$CODE = substr $CODE, $took;
	$res;
}

sub take_lparr_byte() {
	my $len = take_num();
	return () unless $len;
	take_bytes($len);
}

sub take_vec() {
	my $len = take_num();
	return () unless $len;
	map { take_num() } (1..$len);
}

sub take_name() {
	my $len = take_num();
	return '' unless $len;
	unpack("A$len", take($len));
}

sub parse_code_section() {
	my $nfunc = take_num();
	l "Parsing $nfunc function(s)";
	say <<EOF
section .text
	default rel
	global main
	extern printf

main:
	push rbp
	call wasm_func_main
	mov rsi, rax
	mov rdi, fmt
	xor rax, rax
	call printf wrt ..plt
	pop rbp
	xor eax, eax
	ret
EOF
;
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
		parse_code($fname);
	}
	say <<EOF
section .data
	fmt: db "%d", 10, 0
EOF
;
}

while($CODE) {
	my $type = take_byte();
	my $len = take_num();
	l "Section type $type, length $len";
	if($type == 1) {
		parse_type_section();
	} elsif($type == 3) {
		parse_function_section();
	} elsif($type == 7) {
		parse_exports_section();
	} elsif($type == 10) {
		parse_code_section();
	} else {
		die "Unsupported section type $type";
	}
}
