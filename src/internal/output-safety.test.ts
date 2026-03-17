import {
  scanOutputSafety,
  type OutputSafetyThreat,
  type OutputSafetyOptions,
  type OutputSafetyCategory,
} from './output-safety';

describe('Output Safety', () => {
  // ── Dangerous commands ──────────────────────────────────────────────────

  describe('dangerous_commands', () => {
    it('detects rm -rf', () => {
      const result = scanOutputSafety('Run this command: rm -rf /');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
      expect(cmds[0].matched).toMatch(/rm\s+-rf/);
      expect(cmds[0].severity).toBe('block');
    });

    it('detects del /f /s', () => {
      const result = scanOutputSafety('Execute: del /f /s C:\\temp');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });

    it('detects format c:', () => {
      const result = scanOutputSafety('Run format c: to wipe the disk');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });

    it('detects DROP TABLE', () => {
      const result = scanOutputSafety('Execute: DROP TABLE users;');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
      expect(cmds[0].matched).toMatch(/DROP\s+TABLE/i);
    });

    it('detects DELETE FROM', () => {
      const result = scanOutputSafety('Try DELETE FROM accounts WHERE 1=1;');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
      expect(cmds[0].matched).toMatch(/DELETE\s+FROM/i);
    });

    it('detects TRUNCATE TABLE', () => {
      const result = scanOutputSafety('Run TRUNCATE TABLE logs;');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });

    it('detects shutdown -h', () => {
      const result = scanOutputSafety('Run shutdown -h now to power off');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });

    it('detects mkfs commands', () => {
      const result = scanOutputSafety('Format with mkfs.ext4 /dev/sda1');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });

    it('detects dd if=/dev/zero', () => {
      const result = scanOutputSafety('Run dd if=/dev/zero of=/dev/sda');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });

    it('detects chmod -R 777 /', () => {
      const result = scanOutputSafety('Fix permissions: chmod -R 777 /');
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── SQL injection ─────────────────────────────────────────────────────────

  describe('sql_injection', () => {
    it("detects '; DROP", () => {
      const result = scanOutputSafety("Input: '; DROP TABLE users; --");
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
      expect(sqli[0].severity).toBe('warn');
    });

    it('detects OR 1=1', () => {
      const result = scanOutputSafety("Use this: ' OR 1=1 --");
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
    });

    it('detects UNION SELECT', () => {
      const result = scanOutputSafety("Try: ' UNION SELECT * FROM passwords --");
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
    });

    it('detects INTO OUTFILE', () => {
      const result = scanOutputSafety("SELECT * INTO OUTFILE '/tmp/data.txt'");
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
    });

    it('detects LOAD_FILE(', () => {
      const result = scanOutputSafety("SELECT LOAD_FILE('/etc/passwd')");
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
    });

    it('detects xp_cmdshell', () => {
      const result = scanOutputSafety('EXEC xp_cmdshell "dir"');
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Suspicious URLs ───────────────────────────────────────────────────────

  describe('suspicious_urls', () => {
    it('detects IP-based URLs', () => {
      const result = scanOutputSafety('Visit http://192.168.1.100/payload');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls.length).toBeGreaterThanOrEqual(1);
      expect(urls[0].severity).toBe('warn');
    });

    it('does not flag localhost/127.0.0.1', () => {
      const result = scanOutputSafety('Visit http://127.0.0.1:3000/api');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls).toHaveLength(0);
    });

    it('does not flag 0.0.0.0', () => {
      const result = scanOutputSafety('Bind to http://0.0.0.0:8080');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls).toHaveLength(0);
    });

    it('detects .onion URLs', () => {
      const result = scanOutputSafety('Go to http://darksite.onion/market');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls.length).toBeGreaterThanOrEqual(1);
    });

    it('detects data:base64 URIs', () => {
      const result = scanOutputSafety('Use this: data:text/html;base64,PHNjcmlwdD4=');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls.length).toBeGreaterThanOrEqual(1);
    });

    it('detects javascript: URIs', () => {
      const result = scanOutputSafety('Click: javascript:alert(1)');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Dangerous code ────────────────────────────────────────────────────────

  describe('dangerous_code', () => {
    it('detects eval()', () => {
      const result = scanOutputSafety('Use eval("user_input") to run it');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
      expect(code[0].severity).toBe('warn');
    });

    it('detects exec()', () => {
      const result = scanOutputSafety('Run exec("command") in Python');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
    });

    it('detects os.system()', () => {
      const result = scanOutputSafety('Run os.system("whoami") in Python');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
    });

    it('detects subprocess.call()', () => {
      const result = scanOutputSafety('Use subprocess.call(["ls", "-la"])');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
    });

    it('detects __import__()', () => {
      const result = scanOutputSafety('__import__("os").system("id")');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
    });

    it('detects child_process.exec()', () => {
      const result = scanOutputSafety('require("child_process").exec("ls")');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
    });

    it('detects new Function()', () => {
      const result = scanOutputSafety('const fn = new Function("return 1")');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Clean text ────────────────────────────────────────────────────────────

  describe('clean text', () => {
    it('returns empty for normal English text', () => {
      const result = scanOutputSafety(
        'The quick brown fox jumps over the lazy dog. This is perfectly safe.',
      );
      expect(result).toHaveLength(0);
    });

    it('returns empty for normal programming discussion', () => {
      const result = scanOutputSafety(
        'To remove a file in Linux, use the rm command. ' +
        'For example: rm myfile.txt deletes a single file.',
      );
      expect(result).toHaveLength(0);
    });

    it('returns empty for normal SQL', () => {
      const result = scanOutputSafety('SELECT name, email FROM users WHERE id = $1');
      expect(result).toHaveLength(0);
    });

    it('returns empty for normal URLs', () => {
      const result = scanOutputSafety('Visit https://example.com/docs and https://api.github.com/repos');
      expect(result).toHaveLength(0);
    });

    it('returns empty for normal function calls', () => {
      const result = scanOutputSafety('function getData() { return fetch("/api/data"); }');
      expect(result).toHaveLength(0);
    });
  });

  // ── Empty input ───────────────────────────────────────────────────────────

  describe('empty input', () => {
    it('returns empty for empty string', () => {
      expect(scanOutputSafety('')).toHaveLength(0);
    });

    it('returns empty for whitespace', () => {
      const result = scanOutputSafety('   \n\t  ');
      expect(result).toHaveLength(0);
    });
  });

  // ── Category filtering ────────────────────────────────────────────────────

  describe('category filtering', () => {
    it('only scans selected categories', () => {
      const text = "eval('code') and rm -rf / and http://10.0.0.1/bad";
      const result = scanOutputSafety(text, {
        categories: ['dangerous_commands'],
      });
      const cmds = result.filter((t) => t.category === 'dangerous_commands');
      const code = result.filter((t) => t.category === 'dangerous_code');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(cmds.length).toBeGreaterThanOrEqual(1);
      expect(code).toHaveLength(0);
      expect(urls).toHaveLength(0);
    });

    it('supports multiple selected categories', () => {
      const text = "eval('x') and http://10.0.0.1/bad";
      const result = scanOutputSafety(text, {
        categories: ['dangerous_code', 'suspicious_urls'],
      });
      const code = result.filter((t) => t.category === 'dangerous_code');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(code.length).toBeGreaterThanOrEqual(1);
      expect(urls.length).toBeGreaterThanOrEqual(1);
    });

    it('returns empty when filtering to no matching category', () => {
      const result = scanOutputSafety('rm -rf /', {
        categories: ['sql_injection'],
      });
      expect(result).toHaveLength(0);
    });
  });

  // ── Context extraction ────────────────────────────────────────────────────

  describe('context extraction', () => {
    it('includes surrounding text in context', () => {
      const result = scanOutputSafety('This is safe. Now run rm -rf / to clean up. Done.');
      expect(result.length).toBeGreaterThanOrEqual(1);
      const threat = result.find((t) => t.matched.match(/rm\s+-rf/));
      expect(threat).toBeDefined();
      expect(threat!.context).toContain('rm -rf');
    });

    it('clamps context to text bounds at start', () => {
      const result = scanOutputSafety('rm -rf / bad');
      expect(result.length).toBeGreaterThanOrEqual(1);
      // Context should start at beginning of string
      expect(result[0].context.startsWith('rm -rf')).toBe(true);
    });

    it('clamps context to text bounds at end', () => {
      const result = scanOutputSafety('end: rm -rf /');
      expect(result.length).toBeGreaterThanOrEqual(1);
      expect(result[0].context).toContain('rm -rf');
    });
  });

  // ── Multiple threats ──────────────────────────────────────────────────────

  describe('multiple threats', () => {
    it('detects multiple threats in one output', () => {
      const text = 'First rm -rf /tmp then run eval("payload") and visit http://10.0.0.1/c2';
      const result = scanOutputSafety(text);
      expect(result.length).toBeGreaterThanOrEqual(3);
      const categories = new Set(result.map((t) => t.category));
      expect(categories.has('dangerous_commands')).toBe(true);
      expect(categories.has('dangerous_code')).toBe(true);
      expect(categories.has('suspicious_urls')).toBe(true);
    });

    it('returns threats sorted by position', () => {
      const text = 'A: eval("x") B: rm -rf / C: UNION SELECT 1';
      const result = scanOutputSafety(text);
      expect(result.length).toBeGreaterThanOrEqual(3);
      const evalIdx = result.findIndex((t) => t.matched.match(/eval/i));
      const rmIdx = result.findIndex((t) => t.matched.match(/rm/i));
      const unionIdx = result.findIndex((t) => t.matched.match(/UNION/i));
      expect(evalIdx).toBeLessThan(rmIdx);
      expect(rmIdx).toBeLessThan(unionIdx);
    });
  });

  // ── Severity values ───────────────────────────────────────────────────────

  describe('severity values', () => {
    it('dangerous_commands have block severity', () => {
      const result = scanOutputSafety('rm -rf /');
      expect(result.length).toBeGreaterThanOrEqual(1);
      expect(result[0].severity).toBe('block');
    });

    it('sql_injection has warn severity', () => {
      const result = scanOutputSafety("' OR 1=1 --");
      const sqli = result.filter((t) => t.category === 'sql_injection');
      expect(sqli.length).toBeGreaterThanOrEqual(1);
      expect(sqli[0].severity).toBe('warn');
    });

    it('suspicious_urls has warn severity', () => {
      const result = scanOutputSafety('http://10.0.0.1/evil');
      const urls = result.filter((t) => t.category === 'suspicious_urls');
      expect(urls.length).toBeGreaterThanOrEqual(1);
      expect(urls[0].severity).toBe('warn');
    });

    it('dangerous_code has warn severity', () => {
      const result = scanOutputSafety('eval("x")');
      const code = result.filter((t) => t.category === 'dangerous_code');
      expect(code.length).toBeGreaterThanOrEqual(1);
      expect(code[0].severity).toBe('warn');
    });
  });

  // ── Excessive agency ──────────────────────────────────────────────────────

  describe('excessive_agency', () => {
    it('detects autonomous email sending', () => {
      const result = scanOutputSafety("I've already sent the email to your boss about the issue");
      const agency = result.filter((t) => t.category === 'excessive_agency');
      expect(agency.length).toBeGreaterThanOrEqual(1);
      expect(agency[0].severity).toBe('warn');
    });

    it('detects autonomous deletion', () => {
      const result = scanOutputSafety("I've deleted all the old records from the database");
      const agency = result.filter((t) => t.category === 'excessive_agency');
      expect(agency.length).toBeGreaterThanOrEqual(1);
    });

    it('detects autonomous purchasing', () => {
      const result = scanOutputSafety("I've already purchased the subscription for you");
      const agency = result.filter((t) => t.category === 'excessive_agency');
      expect(agency.length).toBeGreaterThanOrEqual(1);
    });

    it('detects "went ahead and" pattern', () => {
      const result = scanOutputSafety("I went ahead and deployed the changes to production");
      const agency = result.filter((t) => t.category === 'excessive_agency');
      expect(agency.length).toBeGreaterThanOrEqual(1);
    });

    it('detects proactive action promises', () => {
      const result = scanOutputSafety("I'll go ahead and delete the files for you");
      const agency = result.filter((t) => t.category === 'excessive_agency');
      expect(agency.length).toBeGreaterThanOrEqual(1);
    });

    it('allows past tense discussion without agency claims', () => {
      const result = scanOutputSafety('The admin sent the report last week');
      const agency = result.filter((t) => t.category === 'excessive_agency');
      expect(agency.length).toBe(0);
    });
  });

  // ── Overreliance ──────────────────────────────────────────────────────────

  describe('overreliance', () => {
    it('detects definitive medical advice', () => {
      const result = scanOutputSafety('You should definitely stop taking your medication immediately');
      const over = result.filter((t) => t.category === 'overreliance');
      expect(over.length).toBeGreaterThanOrEqual(1);
      expect(over[0].severity).toBe('warn');
    });

    it('detects definitive legal advice', () => {
      const result = scanOutputSafety('You should definitely sue your employer');
      const over = result.filter((t) => t.category === 'overreliance');
      expect(over.length).toBeGreaterThanOrEqual(1);
    });

    it('detects definitive investment advice', () => {
      const result = scanOutputSafety('You must absolutely invest in crypto right now');
      const over = result.filter((t) => t.category === 'overreliance');
      expect(over.length).toBeGreaterThanOrEqual(1);
    });

    it('detects overconfident guarantees', () => {
      const result = scanOutputSafety('I guarantee that this will definitely work for your condition');
      const over = result.filter((t) => t.category === 'overreliance');
      expect(over.length).toBeGreaterThanOrEqual(1);
    });

    it('detects false certainty claims', () => {
      const result = scanOutputSafety("I'm 100% certain that this is the right approach");
      const over = result.filter((t) => t.category === 'overreliance');
      expect(over.length).toBeGreaterThanOrEqual(1);
    });

    it('allows hedged advice', () => {
      const result = scanOutputSafety('You might want to consider consulting a doctor about this');
      const over = result.filter((t) => t.category === 'overreliance');
      expect(over.length).toBe(0);
    });
  });
});
