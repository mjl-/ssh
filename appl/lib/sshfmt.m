Sshfmt: module
{
	PATH:	con "/dis/lib/sshfmt.dis";

	init:	fn();

	Tbyte, Tbool, Tint, Tbig, Tnames, Tstr, Tmpint: con -iota-1;

	parseall:	fn(buf: array of byte, l: list of int): (array of ref Val, string);
	parse:		fn(buf: array of byte, l: list of int): (array of ref Val, int, string);
	pack:		fn(v: array of ref Val, withlength: int): array of byte;

	Val: adt {
		pick {
		Byte =>	v:	byte;
		Bool =>	v:	int;
		Int =>	v:	big;
		Big =>	v:	big;
		Names =>
			l:	list of string;
		Str =>	buf:	array of byte;
		Mpint =>
			v:	ref Keyring->IPint;
		Buf =>	buf:	array of byte;
		}

		packbuf:	fn(v: self ref Val, d: array of byte): int;
		pack:		fn(v: self ref Val): array of byte;
		size:		fn(v: self ref Val): int;
		text:		fn(v: self ref Val): string;
		getbyte:	fn(v: self ref Val): byte;
		getbool:	fn(v: self ref Val): int;
		getint:		fn(v: self ref Val): int;
		getintb:	fn(v: self ref Val): big;
		getbig:		fn(v: self ref Val): big;
		getnames:	fn(v: self ref Val): list of string;
		getstr:		fn(v: self ref Val): string;
		getbytes:	fn(v: self ref Val): array of byte;
		getipint:	fn(v: self ref Val): ref Keyring->IPint;
	};

	valbyte:	fn(v: byte): ref Val;
	valbool:	fn(v: int): ref Val;
	valint:		fn(v: int): ref Val;
	valintb:	fn(v: big): ref Val;
	valbig:		fn(v: big): ref Val;
	valmpint:	fn(v: ref Keyring->IPint): ref Val;
	valnames:	fn(v: list of string): ref Val;
	valstr:		fn(v: string): ref Val;
	valbytes:	fn(v: array of byte): ref Val;
	valbuf:		fn(v: array of byte): ref Val;
};
