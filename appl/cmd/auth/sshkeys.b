implement Sshkeys;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
	draw: Draw;
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "env.m";
	env: Env;
include "string.m";
	str: String;
include "tk.m";
	tk: Tk;
include "tkclient.m";
	tkclient: Tkclient;
include "util0.m";
	util: Util0;
	l2a, rev, fail, warn: import util;

Sshkeys: module {
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};


dflag: int;
top: ref Tk->Toplevel;
wmctl: chan of string;

tkcmds0 := array[] of {
"frame .f",
"text .f.t -yscrollcommand {.f.scrolly set} -wrap word",
".f.t insert 1.0 'Waiting for request...",
"scrollbar .f.scrolly -command {.f.t yview}",
"frame .c",
"button .c.deny -command {send cmd deny} -text 'Deny",
"button .c.once -command {send cmd once} -text 'Allow once",
"button .c.add -command {send cmd add} -text 'Allow & Store key",
"button .c.replace -command {send cmd replace} -text 'Allow & Replace existing key(s)",
"pack .f.scrolly -side left -fill y",
"pack .f.t -fill both -expand 1",
"pack .f -fill both -expand 1",
"pack .c -fill x",
"pack propagate . 0",
". configure -width 600 -height 300",
};

init(ctxt: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	if(ctxt == nil)
		fail("no window context");
	draw = load Draw Draw->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	env = load Env Env->PATH;
	tk = load Tk Tk->PATH;
	tkclient = load Tkclient Tkclient->PATH;
	util = load Util0 Util0->PATH;
	util->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-d]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(args != nil)
		arg->usage();

	fio := sys->file2chan("/chan", "sshkeys");
	if(fio == nil)
		fail(sprint("/chan/sshkeys: %r"));

	tkclient->init();
	(top, wmctl) = tkclient->toplevel(ctxt, "", "Sshkeys", Tkclient->Appl);

	tkcmdchan := chan of string;
	tk->namechan(top, tkcmdchan, "cmd");
	for(i := 0; i < len tkcmds0; i++)
		tkcmd(tkcmds0[i]);

	tkclient->onscreen(top, nil);
	tkclient->startinput(top, "kbd"::"ptr"::nil);
	tkclient->wmctl(top, "task");

	fiowrite := fio.write;

	request: array of byte;
	respondc: Sys->Rwrite;
	keys, existing: list of ref Entry;  # existing keys, possibly to be replaced
	new: ref Entry;

	for(;;) alt {
	s := <-top.ctxt.kbd =>
		tk->keyboard(top, s);

	s := <-top.ctxt.ptr =>
		tk->pointer(top, *s);

	s := <-top.ctxt.ctl or
	s = <-top.wreq =>
		tkclient->wmctl(top, s);

	menu := <-wmctl =>
		case menu {
		"exit" =>
			if(respondc != nil)
				respondc <-= (-1, "host key denied");
			return;
		* =>
			tkclient->wmctl(top, menu);
		}

	cmd := <-tkcmdchan =>
		if(respondc != nil) {
			case cmd {
			"deny" =>	respondc <-= (-1, "host key denied");
			"once" or
			"add" or
			"replace" =>	respondc <-= (len request, nil);
			}

			case cmd {
			"add" =>
				f := keysfile();
				fd := sys->open(f, Sys->OWRITE);
				if(fd == nil || sys->seek(fd, big 0, Sys->SEEKEND) < big 0 || sys->fprint(fd, "%s\n", new.text()) < 0)
					warn(sprint("adding key to %q: %r", f));

			"replace" =>
				keys = filter(keys, existing);
				s := "";
				for(; keys != nil; keys = tl keys)
					s += (hd keys).text()+"\n";
				s += new.text()+"\n";
				f := keysfile();
				fd := sys->open(f, Sys->OWRITE|Sys->OTRUNC);
				if(fd == nil || sys->fprint(fd, "%s", s) < 0)
					warn(sprint("rewriting %q: %r", f));
			}

			case cmd {
			"deny" or
			"once" or
			"add" or
			"replace" =>
				tkcmd(".f.t delete 1.0 end");
				tkcmd(".f.t insert 1.0 'Waiting for request...");
				tkcmd("pack forget .c.deny .c.once .c.add .c.replace");
				tkcmd("update");
				tkclient->wmctl(top, "task");
				fiowrite = fio.write;
				request = nil;
				respondc = nil;
				keys = nil;
				new = nil;
			}
		}

	(nil, nil, nil, rc) := <-fio.read =>
		if(rc != nil)
			rc <-= (nil, "permission denied");

	(nil, buf, nil, wc) := <-fiowrite =>
		if(wc == nil)
			break;

		t := l2a(str->unquoted(string buf));
		if(len t != 4) {
			wc <-= (-1, "bad argument");
			break;
		}
		e := ref Entry (t[0], t[1], t[2], t[3]);

		err: string;
		(keys, err) = readkeys();
		if(err != nil) {
			wc <-= (-1, err);
			break;
		}

		(nil, matches, badkeys, otheralgs) := split(keys, e);
		if(matches != nil) {
			wc <-= (len buf, nil);
			break;
		}

		msg: string;
		existing = nil;
		if(badkeys != nil) {
			existing = badkeys;
			msg = sprint("Conflicting host key for address %q, algorithm %#q!\nThis could be a man-in-the-middle attack!", e.addr, e.alg);
			tkcmd("pack .c.deny .c.once .c.add .c.replace -side left -fill x -expand 1");
		} else if(otheralgs != nil) {
			existing = otheralgs;
			msg = sprint("Received host key for address %q with different algorithm then recorded.", e.addr);
			tkcmd("pack .c.deny .c.once .c.add .c.replace -side left -fill x -expand 1");
		} else {
			msg = sprint("First connection to address %q.\nPlease verify this is the correct key.", e.addr);
			tkcmd("pack .c.deny .c.once .c.add -side left -fill x -expand 1");
		}

		msg += sprint("\n\nRemote claims:\nAddress: %s\nAlgorithm: %s\nFingerprint: %s\nHost key:\n%s\n\n", e.addr, e.alg, e.fp, e.hostkey);
		if(existing != nil) {
			msg += sprint("Existing keys for address %q are:\n", e.addr);
			for(r := existing; r != nil; r = tl r) {
				ee := hd r;
				msg += sprint("Algorithm: %s\nFingerprint: %s\nHost key:\n%s\n\n", ee.alg, ee.fp, ee.hostkey);
			}
		}
		tkcmd(".f.t delete 1.0 end; .f.t insert 1.0 '"+msg);
		tkcmd("update");
		tkclient->wmctl(top, "unhide");

		new = e;
		request = buf;
		respondc = wc;
		fiowrite = chan of (int, array of byte, int, Sys->Rwrite);
	}
}

keysfile(): string
{
	return env->getenv("home")+"/lib/sshkeys";
}

Entry: adt {
	addr,	
	alg,
	fp,
	hostkey:	string;

	text:	fn(e: self ref Entry): string;
};

Entry.text(e: self ref Entry): string
{
	return sprint("%q %q %q %q", e.addr, e.alg, e.fp, e.hostkey);
}

filter(l: list of ref Entry, del: list of ref Entry): list of ref Entry
{
	r: list of ref Entry;
	for(; l != nil; l = tl l)
		if(!has(del, hd l))
			r = hd l::r;
	return rev(r);
}

has[T](l: list of T, e: T): int
{
	for(; l != nil; l = tl l)
		if(hd l == e)
			return 1;
	return 0;
}

readkeys(): (list of ref Entry, string)
{
	f := keysfile();
	b := bufio->open(f, Bufio->OREAD);
	if(b == nil)
		return (nil, nil);
	n := 0;
	l: list of ref Entry;
	for(;;) {
		s := b.gets('\n');
		if(s == nil)
			break;
		n++;
		if(s[len s-1] == '\n')
			s = s[:len s-1];
		t := l2a(str->unquoted(s));
		if(len t != 4)
			return (nil, sprint("%s:%d: malformed line", f, n));
		e := ref Entry (t[0], t[1], t[2], t[3]);
		l = e::l;
	}
	return (rev(l), nil);
}

split(l: list of ref Entry, ee: ref Entry): (list of ref Entry, list of ref Entry, list of ref Entry, list of ref Entry)
{
	otheraddr,
	match,
	badkey,
	otheralg: list of ref Entry;

	for(; l != nil; l = tl l) {
		e := hd l;
		if(e.addr != ee.addr)
			otheraddr = e::otheraddr;
		else if(e.alg != ee.alg)
			otheralg = e::otheralg;
		else if(e.fp != ee.fp || e.hostkey != ee.hostkey)
			badkey = e::badkey;
		else
			match = e::match;
	}
	return (rev(otheraddr), rev(match), rev(badkey), rev(otheralg));
}

tkcmd(s: string): string
{
	r := tk->cmd(top, s);
	if(r != nil && r[0] == '!')
		warn(sprint("tkcmd: %q: %s", s, r));
	return r;
}

say(s: string)
{
	if(dflag)
		warn(s);
}
