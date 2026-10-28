import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { simpleParser } from 'mailparser';
import { accountSchema } from '../src/config.js';
import { MailService, encodeRef, LIMITS } from '../src/mail.js';
import {
  readableText,
  textPage,
  inspectStructure,
  attachmentChunk,
  READ_LIMITS,
} from '../src/read-content.js';

const account = accountSchema.parse({
  id: 'test',
  email: 'sender@example.com',
  username: 'sender@example.com',
  password: 'synthetic-only',
  imapHost: 'imap.strato.de',
  smtpHost: 'smtp.strato.de',
});
const id = encodeRef({ account: 'test', folder: 'INBOX', validity: '123', uid: 7 });
const attachment = {
  part: '2',
  type: 'application/octet-stream',
  disposition: 'attachment',
  dispositionParameters: { filename: '../../untrusted.bin' },
  size: 12 * 1024 * 1024,
};
const structure = {
  type: 'multipart/mixed',
  childNodes: [
    {
      part: '1',
      type: 'multipart/alternative',
      childNodes: [
        { part: '1.1', type: 'text/plain' },
        { part: '1.2', type: 'text/html' },
      ],
    },
    attachment,
  ],
};

function fixture(
  parts: Record<string, Buffer> = {
    '1.1': Buffer.from(' \r\n'),
    '1.2': Buffer.from('<p>Readable HTML ä</p>'),
    '2': Buffer.alloc(LIMITS.chunk + 19, 123),
  },
  tree = structure,
) {
  const calls: any[] = [];
  const c = Object.assign(new EventEmitter(), {
    mailbox: { uidValidity: 123n, readOnly: true },
    async connect() {},
    close() {},
    async getMailboxLock(_: string, opts: any) {
      assert.equal(opts.readOnly, true);
      return { release() {} };
    },
    async fetchOne(_: number, q: any) {
      assert.ok(!q.source, 'large messages must not fetch the entire source');
      return {
        size: 20 * 1024 * 1024,
        uid: 7,
        bodyStructure: tree,
        flags: new Set(['\\Flagged']),
        envelope: { subject: 'Synthetic large message' },
      };
    },
    async download(uid: number, part: string, opts: any) {
      calls.push({ uid, part, opts });
      assert.equal(opts.uid, true);
      const b = parts[part];
      if (!b) return {};
      return {
        meta: {
          expectedSize: 20 * 1024 * 1024,
          filename: '../../untrusted.bin',
          contentType: part === '2' ? 'application/octet-stream' : 'text/plain',
        },
        content: Readable.from([b.subarray(0, opts.maxBytes)]),
      };
    },
  });
  return { c, calls, service: new MailService([account], () => c as any) };
}

test('empty MIME plain alternative falls back to HTML; no script text and no network fetching', async () => {
  const raw = [
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary=x',
    '',
    '--x',
    'Content-Type: text/plain',
    '',
    '',
    '--x',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Actual body &amp; ä</p><script>BAD_SCRIPT</script><img src="https://example.com/tracker">',
    '--x--',
    '',
  ].join('\r\n');
  const parsed = await simpleParser(raw, { skipHtmlToText: false, skipTextToHtml: true });
  assert.equal(parsed.text?.trim() || '', '');
  assert.match(readableText(parsed), /Actual body & ä/);
  assert.ok(!readableText(parsed).includes('BAD_SCRIPT'));
  assert.equal(readableText({ text: 'Plain chosen', html: '<p>Other</p>' }), 'Plain chosen');
});

test('text pages reconstruct every character and reject invalid cursors', () => {
  const input = 'x'.repeat(50000) + 'ä😀tail';
  const a = textPage(input, 0),
    b = textPage(input, a.nextTextOffset!);
  assert.equal(a.text + b.text, input);
  assert.equal(b.nextTextOffset, null);
  assert.equal(b.textTruncated, false);
  assert.throws(() => textPage(input, -1), /offset/);
  assert.throws(() => textPage(input, input.length + 1), /offset/);
});

test('large mail reads only body parts, falls back to HTML and retains stable attachment indexes', async () => {
  const f = fixture(),
    r = await f.service.read('test', id);
  assert.match(r.text, /Readable HTML ä/);
  assert.equal(r.bodyLimited, false);
  assert.deepEqual(r.flags, ['\\Flagged']);
  assert.equal(r.attachments[0].index, 0);
  assert.equal(r.attachments[0].size, null);
  assert.deepEqual(
    f.calls.map((c) => c.part),
    ['1.1', '1.2'],
  );
  assert.ok(f.calls.every((c) => c.opts.maxBytes <= READ_LIMITS.textBytes + 1));
});

test('large-mail attachment chunks reconstruct bytes and never report whole-message size', async () => {
  const f = fixture(),
    a = await f.service.attachment('test', id, 0);
  assert.equal(a.size, null);
  assert.equal(a.nextOffset, LIMITS.chunk);
  const b = await f.service.attachment('test', id, 0, a.nextOffset!);
  assert.equal(b.nextOffset, null);
  assert.equal(b.size, LIMITS.chunk + 19);
  assert.deepEqual(
    Buffer.concat([Buffer.from(a.base64, 'base64'), Buffer.from(b.base64, 'base64')]),
    Buffer.alloc(LIMITS.chunk + 19, 123),
  );
  assert.ok(f.calls.every((c) => c.part === '2'));
  await assert.rejects(f.service.attachment('test', id, 0, LIMITS.chunk + 20), /offset/);
});

test('8 MiB body budget is shared across parts and truncation is explicit', async () => {
  const tree = {
    type: 'multipart/mixed',
    childNodes: [
      { part: '1', type: 'text/plain' },
      { part: '2', type: 'text/plain' },
    ],
  };
  const f = fixture(
    { '1': Buffer.alloc(READ_LIMITS.textBytes + 1, 120), '2': Buffer.from('must not fetch') },
    tree as any,
  );
  const r = await f.service.read('test', id);
  assert.equal(r.bodyLimited, true);
  assert.equal(r.totalTextCharacters, READ_LIMITS.textBytes);
  assert.equal(r.nextTextOffset, 50000);
  assert.equal(f.calls.length, 1);
});

test('unsafe MIME trees, absent parts and excessive encoded sizes fail closed', async () => {
  assert.throws(() => inspectStructure(), /unavailable/);
  assert.throws(
    () =>
      inspectStructure({
        type: 'multipart/mixed',
        childNodes: Array.from({ length: 1001 }, () => ({ type: 'text/plain' })),
      }),
    /safety/,
  );
  const f = fixture({});
  await assert.rejects(f.service.read('test', id), /not found/);
  await assert.rejects(
    attachmentChunk(
      f.c as any,
      7,
      { ...attachment, size: READ_LIMITS.encodedAttachment + 1 },
      0,
      LIMITS.chunk,
    ),
    /192 MiB/,
  );
});

test('stream errors propagate rather than returning a silently shortened attachment', async () => {
  const c = {
    async download() {
      return {
        meta: {},
        content: Readable.from(
          (async function* () {
            yield Buffer.from('partial');
            throw Error('Synthetic transport failure');
          })(),
        ),
      };
    },
  };
  await assert.rejects(
    attachmentChunk(c as any, 7, attachment, 0, LIMITS.chunk),
    /Synthetic transport failure/,
  );
});

test('decoded attachment cap is enforced while retaining only the requested chunk', async () => {
  const c = {
    async download() {
      return {
        meta: {},
        content: Readable.from(
          (async function* () {
            for (let i = 0; i < 129; i++) yield Buffer.alloc(1024 * 1024);
          })(),
        ),
      };
    },
  };
  await assert.rejects(
    attachmentChunk(c as any, 7, attachment, READ_LIMITS.attachment, LIMITS.chunk),
    /128 MiB/,
  );
});
