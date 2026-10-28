import type { ImapFlow, MessageStructureObject } from 'imapflow';
import { htmlToText } from 'html-to-text';

export class MailError extends Error {}
export const READ_LIMITS = {
  textBytes: 8 * 1024 * 1024,
  attachment: 128 * 1024 * 1024,
  encodedAttachment: 192 * 1024 * 1024,
  parts: 1000,
  depth: 30,
} as const;

export function readableText(message: { text?: string; html?: string | false }) {
  if (message.text?.trim()) return message.text;
  if (!message.html) return message.text ?? '';
  return htmlToText(message.html, {
    wordwrap: false,
    limits: { maxInputLength: READ_LIMITS.textBytes },
  });
}

export function textPage(text: string, offset: number, length = 50000) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > text.length)
    throw new MailError('Text offset out of range');
  const end = Math.min(offset + length, text.length);
  return {
    text: text.slice(offset, end),
    textOffset: offset,
    totalTextCharacters: text.length,
    nextTextOffset: end < text.length ? end : null,
    textTruncated: end < text.length,
  };
}

const typeOf = (n: MessageStructureObject) => (n.type ?? '').toLowerCase();
function isAttachment(n: MessageStructureObject) {
  return (
    n.disposition?.toLowerCase() === 'attachment' ||
    (!typeOf(n).startsWith('multipart/') && !['text/plain', 'text/html'].includes(typeOf(n)))
  );
}

export function inspectStructure(root?: MessageStructureObject) {
  if (!root) throw new MailError('MIME structure unavailable; cannot safely read message parts');
  const attachments: MessageStructureObject[] = [];
  let nodes = 0;
  function visit(n: MessageStructureObject, depth: number) {
    if (++nodes > READ_LIMITS.parts || depth > READ_LIMITS.depth)
      throw new MailError('Message MIME structure exceeds safety limits');
    // Validate the entire tree, including embedded messages, before any downloads.
    for (const child of n.childNodes ?? []) visit(child, depth + 1);
  }
  visit(root, 0);
  function collect(n: MessageStructureObject) {
    if (isAttachment(n)) {
      attachments.push(n);
      return;
    }
    for (const child of n.childNodes ?? []) collect(child);
  }
  collect(root);
  return { root, attachments };
}

function partId(node: MessageStructureObject) {
  const part = node.part || '1';
  if (!/^\d+(\.\d+)*$/.test(part)) throw new MailError('Invalid MIME part identifier');
  return part;
}

/** Read only body parts, with one shared budget across the complete MIME tree. */
export async function readBodyParts(c: ImapFlow, uid: number, root: MessageStructureObject) {
  let remaining: number = READ_LIMITS.textBytes;
  let bodyLimited = false;
  async function read(n: MessageStructureObject): Promise<string> {
    if (isAttachment(n)) return '';
    const type = typeOf(n);
    if (type.startsWith('multipart/')) {
      const children = n.childNodes ?? [];
      if (type === 'multipart/alternative') {
        // Prefer plain text, but a blank alternative must not hide readable HTML.
        const ordered = [...children].sort(
          (a, b) => Number(typeOf(b) === 'text/plain') - Number(typeOf(a) === 'text/plain'),
        );
        for (const child of ordered) {
          const text = await read(child);
          if (text.trim()) return text;
        }
        return '';
      }
      const chunks: string[] = [];
      for (const child of children) {
        const text = await read(child);
        if (text) chunks.push(text);
      }
      return chunks.join('\n');
    }
    if (remaining <= 0) {
      bodyLimited = true;
      return '';
    }
    const { content } = await c.download(uid, partId(n), {
      uid: true,
      maxBytes: remaining + 1,
      chunkSize: 64 * 1024,
    });
    if (!content) throw new MailError('Message body part not found; search again');
    const chunks: Buffer[] = [];
    let bytes = 0;
    try {
      for await (const value of content) {
        const chunk = Buffer.from(value);
        const take = Math.min(chunk.length, remaining - bytes);
        if (take > 0) chunks.push(chunk.subarray(0, take));
        bytes += take;
        if (chunk.length > take) {
          bodyLimited = true;
          break;
        }
      }
    } finally {
      content.destroy();
    }
    remaining -= bytes;
    const value = Buffer.concat(chunks, bytes).toString('utf8');
    return type === 'text/html' ? readableText({ html: value }) : value;
  }
  const text = await read(root);
  return { text, bodyLimited };
}

/** Decoded byte offsets; only the requested chunk is retained in memory. */
export async function attachmentChunk(
  c: ImapFlow,
  uid: number,
  node: MessageStructureObject,
  offset: number,
  chunkSize: number,
) {
  if ((node.size ?? 0) > READ_LIMITS.encodedAttachment)
    throw new MailError('Encoded attachment exceeds 192 MiB safety limit');
  const budget = Math.min(offset + chunkSize + 1, READ_LIMITS.attachment + 1);
  const { content, meta } = await c.download(uid, partId(node), {
    uid: true,
    maxBytes: budget,
    chunkSize: 64 * 1024,
  });
  if (!content) throw new MailError('Attachment not found');
  let consumed = 0;
  const chunks: Buffer[] = [];
  try {
    for await (const value of content) {
      const chunk = Buffer.from(value);
      const start = Math.max(0, offset - consumed);
      const end = Math.min(chunk.length, offset + chunkSize + 1 - consumed);
      if (end > start) chunks.push(chunk.subarray(start, end));
      consumed += chunk.length;
      if (consumed > READ_LIMITS.attachment)
        throw new MailError('Attachment exceeds 128 MiB download limit');
      if (consumed >= budget) break;
    }
  } finally {
    content.destroy();
  }
  if (offset > consumed) throw new MailError('Attachment offset out of range');
  const data = Buffer.concat(chunks);
  const more = data.length > chunkSize;
  return {
    filename: meta.filename,
    contentType: meta.contentType || node.type,
    // RFC822.SIZE is the whole message; it must never be reported as a part's size.
    size: more ? null : consumed,
    encodedSize: node.size ?? null,
    offset,
    base64: data.subarray(0, chunkSize).toString('base64'),
    nextOffset: more ? offset + chunkSize : null,
  };
}
