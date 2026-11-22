/*! Eretek Online Araçlar #70 — Ağ Kuralı Politika Matrisi */
ERT.def('70', {
	run: function (v, c) {
		var IP = ERT.ip, r = c.csv(v.csv, 'csv', 2000), H = r.head, col = function (n) { return ERT.csv.col(H, n); };
		var iI = col(['id', 'rule', 'kural']), iA = col(['action', 'eylem', 'aktion']), iS = col(['src', 'source', 'kaynak', 'quelle']), iD = col(['dst', 'destination', 'hedef', 'ziel']), iP = col(['proto', 'protocol', 'protokol']), iT = col(['port', 'dport', 'ports']);
		if (iA < 0 || iS < 0 || iD < 0) { throw c.fe('csv', 'col', { c: 'action, src, dst, proto, port' }); }
		var net = function (s, row) {
			s = String(s || '').trim().toLowerCase();
			if (s === 'any' || s === '*' || s === '' || s === 'herhangi' || s === 'alle') { return { any: true }; }
			var x = IP.parseCidr(s); if (x.err) { throw c.fe('csv', 'rowAddr', { r: row, a: s }); } return x;
		};
		var pr = function (s, row) { s = ERT.norm(s || 'any'); if (s === 'any' || s === '*' || s === 'ip') { return 'any'; } if (/^(tcp|udp|icmp|icmpv6|esp|gre)$/.test(s)) { return s; } throw c.fe('csv', 'rowProto', { r: row, p: s }); };
		var pt = function (s, row) {
			s = String(s || '').trim().toLowerCase(); if (s === '' || s === 'any' || s === '*') { return [0, 65535]; }
			var m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(s); if (!m || +m[1] > 65535 || (m[2] && (+m[2] > 65535 || +m[2] < +m[1]))) { throw c.fe('csv', 'rowPort', { r: row, p: s }); }
			return [+m[1], m[2] ? +m[2] : +m[1]];
		};
		var act = function (s, row) { s = ERT.norm(s); if (/^(allow|permit|accept|izin|erlauben|pass)$/.test(s)) { return 'allow'; } if (/^(deny|drop|reject|block|engelle|reddet|verweigern|blockieren)$/.test(s)) { return 'deny'; } throw c.fe('csv', 'rowAct', { r: row, a: s }); };
		var R = r.rows.map(function (x, i) { var row = i + 2; return { id: iI >= 0 && x[iI] ? x[iI] : String(i + 1), a: act(x[iA], row), s: net(x[iS], row), d: net(x[iD], row), p: iP >= 0 ? pr(x[iP], row) : 'any', t: iT >= 0 ? pt(x[iT], row) : [0, 65535], raw: x }; });
		var cn = function (a, b) { return a.any || (!b.any && a.fam === b.fam && b.net >= a.net && b.last <= a.last); }; // a ⊇ b
		var cp = function (a, b) { return a === 'any' || a === b; };
		var ctp = function (a, b) { return a[0] <= b[0] && a[1] >= b[1]; };
		var risky = { 22: 'SSH', 23: 'Telnet', 445: 'SMB', 3389: 'RDP', 1433: 'MSSQL', 3306: 'MySQL', 5900: 'VNC', 161: 'SNMP' };
		var rows = [], cls = [], res = [];
		R.forEach(function (x, j) {
			var f = [], lvl = 'ok';
			for (var i = 0; i < j; i++) { var y = R[i]; if (cn(y.s, x.s) && cn(y.d, x.d) && cp(y.p, x.p) && ctp(y.t, x.t)) { f.push(c.t(y.a === x.a ? 'redundant' : 'shadow', { r: y.id })); lvl = y.a === x.a ? 'warn' : 'err'; break; } }
			if (x.a === 'allow' && x.s.any && x.d.any && x.p === 'any' && x.t[0] === 0 && x.t[1] === 65535) { f.push(c.t('anyany')); lvl = 'err'; }
			else if (x.a === 'allow' && x.s.any) { Object.keys(risky).forEach(function (p) { if (+p >= x.t[0] && +p <= x.t[1] && x.p !== 'icmp') { f.push(c.t('riskyPort', { p: p, n: risky[p] })); if (lvl === 'ok') { lvl = 'warn'; } } }); }
			if (x.a === 'allow' && (x.t[1] - x.t[0]) > 1000 && !(x.t[0] === 0 && x.t[1] === 65535 && x.s.any && x.d.any)) { f.push(c.t('wide', { n: x.t[1] - x.t[0] + 1 })); if (lvl === 'ok') { lvl = 'warn'; } }
			var fmtN = function (n) { return n.any ? 'any' : IP.str(n); };
			rows.push([x.id, c.t('a_' + x.a), fmtN(x.s), fmtN(x.d), x.p, x.t[0] === 0 && x.t[1] === 65535 ? 'any' : (x.t[0] === x.t[1] ? x.t[0] : x.t[0] + '-' + x.t[1]), f.join('; ') || '–']);
			cls.push(lvl); res.push(lvl);
		});
		var msgs = [], hit = null;
		if (v.tsrc || v.tdst) {
			var ts = IP.parse(v.tsrc || ''), td = IP.parse(v.tdst || '');
			if (!ts) { throw c.fe('tsrc', 'ip'); } if (!td) { throw c.fe('tdst', 'ip'); }
			var tp = v.tproto || 'tcp', tport = v.tport === null || v.tport === undefined ? null : v.tport;
			var inN = function (n, a) { return n.any || (n.fam === a.fam && a.v >= n.net && a.v <= n.last); };
			for (var k = 0; k < R.length; k++) { var z = R[k]; if (inN(z.s, ts) && inN(z.d, td) && (z.p === 'any' || z.p === tp) && (tport === null || (tport >= z.t[0] && tport <= z.t[1]))) { hit = z; break; } }
			var pk = (v.tsrc + ' → ' + v.tdst + ' ' + tp + (tport !== null ? '/' + tport : ''));
			msgs.push(hit ? [hit.a === 'allow' ? 'ok' : 'err', c.t('hit', { p: pk, r: hit.id, a: c.t('a_' + hit.a) })] : ['warn', c.t('noHit', { p: pk })]);
		}
		var nErr = res.filter(function (x) { return x === 'err'; }).length, nWarn = res.filter(function (x) { return x === 'warn'; }).length;
		msgs.push(nErr || nWarn ? [nErr ? 'err' : 'warn', c.t('sum', { e: nErr, w: nWarn })] : ['ok', c.t('clean')], ['info', c.t('first')], ['info', c.t('implicit')]);
		var cols = ['#', c.t('c_a'), c.t('c_s'), c.t('c_d'), c.t('c_p'), c.t('c_t'), c.t('c_f')];
		return { big: c.t('big', { n: R.length, e: nErr, w: nWarn }), msgs: msgs, tables: [{ cols: cols, rows: rows, cls: cls }], x: { csv: { name: 'firewall-rules', cols: cols, rows: rows } }, v: { levels: res, hit: hit ? hit.id : null } };
	}
});
