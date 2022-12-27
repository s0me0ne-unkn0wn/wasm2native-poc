#!/usr/bin/perl

use v5.30.0;
use File::Slurp;
use List::Util qw(sum);
use DDP;
use feature qw(signatures);
no warnings qw(experimental::signatures);

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
		my ($etype, $npar, $nres, $rtype) = unpack('CCCC', take(4));
		die "  Unknown entity type $etype" unless $etype == 0x60;
		l "  Function with $npar param(s) and $nres result(s), result type $rtype";
		$TYPE[$i] = { npar => $npar, nres => $nres, rtype => $rtype };
	}
}

sub parse_function_section() {
	my $nfunc = unpack('C', take(1));
	l "Parsing $nfunc function index(es)";
	for(my $i = 0; $i < $nfunc; $i++) {
		my $index = unpack('C', take(1));
		l "  Function index $index";
		$FTYPE[$i] = { type => $index };
	}
}

sub parse_exports_section() {
	my $nexp = unpack('C', take(1));
	l "Parsing $nexp export(s)";
	for (1..$nexp) {
		my $nlen = unpack('C', take(1));
		my ($name, $kind, $index) = unpack("A$nlen C C", take($nlen + 2));
		l "  Export '$name', of kind $kind, index $index";
		if($kind == 0) {
			$EXPORT[$index] = { name => $name };
		} else {
			die "Unsupported export kind $kind";
		}
	}
}

my %OPCODE = (
	0x0b => { name => 'eof' },
	0x0f => { name => 'return', code => [ 'pop rax', 'ret' ] },
	0x41 => { name => 'i32.const \0', args => 1, code => [ 'push \0' ] },
	0x6a => { name => 'i32.add', code => [ 'pop rax', 'add [rsp], rax' ] },
	0x6b => { name => 'i32.sub', code => [ 'pop rax', 'sub [rsp], rax' ] },
);


sub parse_code($code) {
	my @inst = unpack('C*', $code);
	my $pc = 0;
	while($pc < @inst) {
		my $op = $inst[$pc++];
		if(my $opcode = $OPCODE{$op}) {
			my @args;
			if($opcode->{args}) {
				push @args, leb128(\@inst, \$pc) for 1..$opcode->{args};
			}
			$_ = $opcode->{name};
			s/\\(\d)/$args[$1]/xg;
			say "\t;; $_";
			for ($opcode->{code}->@*) {
				my $o = $_;
				$o =~ s/\\(\d)/$args[$1]/xg;
				say "\t$o";
			}
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

sub parse_code_section() {
	my $nfunc = unpack('C', take(1));
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
		my ($size, $nlocals) = unpack('CC', take(2));
		l "  Function with body size $size, number of locals $nlocals";
		my $code = take($size - 1);
		l "    Code: " . join(' ', map { sprintf '%02X', $_ } unpack('C*', $code));
		parse_code($code);
	}
	say <<EOF
section .data
	fmt: db "%d", 10, 0
EOF
;
}

while($CODE) {
	my ($type, $len) = unpack('CC', take(2));
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
