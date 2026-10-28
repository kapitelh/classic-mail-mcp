import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type TLSSocket } from 'node:tls';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { ImapFlow } from 'imapflow';
import { MailService, imapOptions } from '../src/mail.js';
import { accountSchema } from '../src/config.js';
const account = accountSchema.parse({
  id: 'synthetic',
  email: 'test@example.com',
  username: 'test@example.com',
  password: 'synthetic-only',
  imapHost: 'imap.example.com',
  smtpHost: 'smtp.example.com',
  allowedFolders: ['INBOX'],
});
async function fixture(large = false) {
  const dir = mkdtempSync(join(tmpdir(), 'classic-mail-test-tls-'));
  const key = join(dir, 'key.pem'),
    cert = join(dir, 'cert.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-keyout',
      key,
      '-out',
      cert,
    ],
    { stdio: 'ignore' },
  );
  const ca = readFileSync(cert),
    commands: string[] = [],
    sockets = new Set<TLSSocket>();
  let seen = false;
  const raw = Buffer.from(
    [
      'From: Test <test@example.com>',
      'Subject: Wire test',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b"',
      '',
      '--b',
      'Content-Type: text/plain',
      '',
      'Synthetic wire test',
      '--b',
      'Content-Type: application/octet-stream',
      'Content-Disposition: attachment; filename="test.bin"',
      'Content-Transfer-Encoding: base64',
      '',
      'dGVzdA==',
      '--b--',
      '',
    ].join('\r\n'),
  );
  const server = createServer(
    { key: readFileSync(key), cert: ca, minVersion: 'TLSv1.2' },
    (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', () => {});
      socket.write('* OK [CAPABILITY IMAP4rev1] synthetic server\r\n');
      let pending = '';
      socket.on('data', (chunk) => {
        pending += chunk.toString();
        let i;
        while ((i = pending.indexOf('\r\n')) >= 0) {
          const line = pending.slice(0, i);
          pending = pending.slice(i + 2);
          const [tag, ...pieces] = line.split(' '),
            cmd = pieces.join(' ');
          // Never retain LOGIN credentials even in test diagnostics.
          commands.push(cmd.startsWith('LOGIN') ? 'LOGIN [redacted]' : cmd);
          const ok = () => socket.write(tag + ' OK done\r\n');
          if (cmd === 'CAPABILITY') {
            socket.write('* CAPABILITY IMAP4rev1\r\n');
            ok();
          } else if (cmd.startsWith('LOGIN')) ok();
          else if (cmd.startsWith('LIST') || cmd.startsWith('LSUB')) {
            socket.write('* LIST () "/" "INBOX"\r\n');
            ok();
          } else if (cmd.startsWith('STATUS')) {
            socket.write(
              '* STATUS "INBOX" (MESSAGES 1 UNSEEN ' + (seen ? 0 : 1) + ' UIDVALIDITY 123)\r\n',
            );
            ok();
          } else if (cmd.startsWith('EXAMINE')) {
            socket.write(
              '* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n* OK [UIDVALIDITY 123]\r\n* OK [UIDNEXT 8]\r\n' +
                tag +
                ' OK [READ-ONLY] done\r\n',
            );
          } else if (cmd.startsWith('UID SEARCH')) {
            socket.write('* SEARCH 7\r\n');
            ok();
          } else if (cmd.startsWith('UID FETCH')) {
            if (/BODY\[/.test(cmd)) seen = true;
            if (large) {
              const text = Buffer.from('Synthetic large body');
              const binary = Buffer.alloc(150000, 42);
              const encoded = Buffer.from(
                binary
                  .toString('base64')
                  .match(/.{1,76}/g)!
                  .join('\r\n'),
              );
              const sections: Record<string, Buffer> = {
                '1': text,
                '1.mime': Buffer.from('Content-Type: text/plain; charset=utf-8\r\n\r\n'),
                '2': encoded,
                '2.mime': Buffer.from(
                  'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="test.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n',
                ),
              };
              socket.write('* 1 FETCH (UID 7 FLAGS () RFC822.SIZE 20971520');
              if (cmd.includes('BODYSTRUCTURE'))
                socket.write(
                  ' BODYSTRUCTURE (("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" ' +
                    text.length +
                    ' 1 NIL NIL NIL NIL)("APPLICATION" "OCTET-STREAM" NIL NIL NIL "BASE64" ' +
                    encoded.length +
                    ' NIL ("ATTACHMENT" ("FILENAME" "test.bin")) NIL NIL) "MIXED" ("BOUNDARY" "b") NIL NIL NIL)',
                );
              for (const m of cmd.matchAll(/BODY\.PEEK\[([^\]]+)\](?:<(\d+)\.(\d+)>)?/g)) {
                const key = m[1].toLowerCase(),
                  start = Number(m[2] || 0);
                const value = (sections[key] || Buffer.alloc(0)).subarray(
                  start,
                  m[3] ? start + Number(m[3]) : undefined,
                );
                socket.write(
                  ' BODY[' +
                    m[1] +
                    ']' +
                    (m[2] ? '<' + start + '>' : '') +
                    ' {' +
                    value.length +
                    '}\r\n',
                );
                socket.write(value);
              }
              socket.write(')\r\n');
            } else if (cmd.includes('BODY.PEEK')) {
              socket.write('* 1 FETCH (UID 7 FLAGS () BODY[]<0> {' + raw.length + '}\r\n');
              socket.write(raw);
              socket.write(')\r\n');
            } else socket.write('* 1 FETCH (UID 7 FLAGS () RFC822.SIZE ' + raw.length + ')\r\n');
            ok();
          } else if (cmd === 'LOGOUT') {
            socket.write('* BYE\r\n');
            ok();
            socket.end();
          } else {
            if (/SELECT|STORE|APPEND|EXPUNGE/.test(cmd)) seen = true;
            socket.write(tag + ' BAD unsupported\r\n');
          }
        }
      });
    },
  );
  server.on('tlsClientError', () => {});
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  const address = server.address();
  if (!address || typeof address === 'string') throw Error('No test port');
  const make = (options: any = {}) =>
    new ImapFlow({
      ...imapOptions(account),
      host: '127.0.0.1',
      port: address.port,
      tls: { ...imapOptions(account).tls, servername: 'localhost', ca, ...options },
      connectionTimeout: 3000,
      greetingTimeout: 3000,
      socketTimeout: 3000,
    });
  return {
    make,
    commands,
    get seen() {
      return seen;
    },
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
test('real ImapFlow over verified local TLS emits EXAMINE and BODY.PEEK; unread stays unchanged', async () => {
  const f = await fixture();
  try {
    const mail = new MailService([account], () => f.make());
    assert.equal((await mail.listFolders('synthetic')).folders[0].status?.unseen, 1);
    const found = await mail.search('synthetic', 'INBOX', { seen: false }, 25);
    assert.equal(found.messages.length, 1);
    const id = found.messages[0].id;
    const r = await mail.read('synthetic', id),
      a = await mail.attachment('synthetic', id, 0);
    assert.match(r.text, /Synthetic wire test/);
    assert.equal(Buffer.from(a.base64, 'base64').toString(), 'test');
    assert.equal((await mail.listFolders('synthetic')).folders[0].status?.unseen, 1);
    assert.equal(f.seen, false);
    assert.equal(f.commands.filter((c) => c.startsWith('EXAMINE')).length, 3);
    assert.equal(f.commands.filter((c) => c.includes('BODY.PEEK[]<0.8388609>')).length, 2);
    assert.ok(
      !f.commands.some((c) =>
        /^(SELECT|CLOSE|EXPUNGE|APPEND|CREATE|DELETE|RENAME)|^UID (STORE|COPY|MOVE|EXPUNGE)/.test(
          c,
        ),
      ),
    );
  } finally {
    await f.close();
  }
});
test('actual TLS handshake rejects untrusted certificate and wrong server hostname', async () => {
  const f = await fixture();
  try {
    for (const options of [{ ca: undefined }, { servername: 'wrong.example' }]) {
      const c = f.make(options);
      c.on('error', () => {});
      try {
        await assert.rejects(c.connect());
      } finally {
        c.close();
      }
    }
    assert.ok(!f.commands.some((c) => c.startsWith('LOGIN')));
  } finally {
    await f.close();
  }
});

test('real TLS MIME part downloads decode base64 exactly without fetching the large full source', async () => {
  const f = await fixture(true);
  try {
    const mail = new MailService([account], () => f.make());
    const found = await mail.search('synthetic', 'INBOX', {}, 1);
    const id = found.messages[0].id;
    const r = await mail.read('synthetic', id);
    assert.equal(r.text, 'Synthetic large body');
    assert.equal(r.attachments.length, 1);
    const a = await mail.attachment('synthetic', id, 0);
    const b = await mail.attachment('synthetic', id, 0, a.nextOffset!);
    assert.equal(a.size, null);
    assert.equal(b.size, 150000);
    assert.equal(b.nextOffset, null);
    assert.deepEqual(
      Buffer.concat([Buffer.from(a.base64, 'base64'), Buffer.from(b.base64, 'base64')]),
      Buffer.alloc(150000, 42),
    );
    assert.equal(f.seen, false);
    assert.ok(f.commands.some((c) => c.includes('BODY.PEEK[2]')));
    assert.ok(
      !f.commands.some(
        (c) =>
          c.includes('BODY.PEEK[]') || /^(SELECT|CLOSE|EXPUNGE|APPEND)|^UID (STORE|MOVE)/.test(c),
      ),
    );
  } finally {
    await f.close();
  }
});
