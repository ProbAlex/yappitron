import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { readFileSync, existsSync } from 'node:fs';

const MAIL_FILE = process.env.E2E_MAIL_FILE;
/** Deployed runs: read codes back from Resend (recipients are Resend's own test inboxes). */
const RESEND_KEY = process.env.E2E_RESEND_KEY;
const PASSWORD = 'correct horse battery staple';

/** Any request to a host other than the app's own: there must never be one. */
const foreignRequests: string[] = [];

/** Every page a test opened, so a failure can show what each one was displaying. */
const openPages: { who: string; page: Page }[] = [];

test.afterEach(async ({}, info) => {
  if (info.status !== info.expectedStatus) {
    for (const { who, page } of openPages) {
      const tree = await page.locator('body').ariaSnapshot().catch(() => '(page closed)');
      console.log(`--- ${who}'s page at failure ---\n` + tree.split('\n').filter((l) => !/^\s*- (generic:?|textbox)$|button "Submit"/.test(l)).slice(0, 20).join('\n'));
    }
  }
  openPages.length = 0;
});

/** The address a test account signs up with. */
const emailFor = (username: string) =>
  RESEND_KEY ? `delivered+${username}@resend.dev` : `${username}@example.test`;

async function codeFromFile(to: string): Promise<string | undefined> {
  if (!MAIL_FILE || !existsSync(MAIL_FILE)) return undefined;
  const mails = readFileSync(MAIL_FILE, 'utf8').trim().split('\n').filter(Boolean)
    .map((l) => JSON.parse(l)).filter((m) => m.to === to);
  return mails.length ? /(\d{6})/.exec(mails[0].subject)![1] : undefined;
}

async function codeFromResend(to: string): Promise<string | undefined> {
  const res = await fetch('https://api.resend.com/emails?limit=40', { headers: { authorization: `Bearer ${RESEND_KEY}` } });
  if (!res.ok) return undefined; // Resend allows 2 requests/second; the caller retries
  const { data } = (await res.json()) as { data: { to: string[]; subject: string }[] };
  const mail = data.find((m) => m.to.includes(to));
  return mail ? /code: (\d{6})/.exec(mail.subject)?.[1] : undefined;
}

/** The verification code emailed to `to`. */
async function codeFor(to: string): Promise<string> {
  for (let i = 0; i < 80; i++) {
    const code = RESEND_KEY ? await codeFromResend(to) : await codeFromFile(to);
    if (code) return code;
    await new Promise((r) => setTimeout(r, RESEND_KEY ? 1500 : 100));
  }
  throw new Error(`no email for ${to}`);
}

/**
 * Type into a Flutter text field found by its accessible name. Flutter focuses (and with
 * `autofocus`, re-creates) its hidden <input> asynchronously, so typed characters can be lost;
 * check the field's value and retry.
 */
async function fill(page: Page, name: string | RegExp, text: string) {
  const field = page.getByRole('textbox', { name, exact: typeof name === 'string' });
  await field.waitFor();
  // A field that appears with `autofocus` takes focus by itself, and Flutter then attaches its
  // text-input connection a moment later, resetting the DOM input to its own (empty) state.
  // Typing during that window is lost. So: let autofocus finish, otherwise focus it ourselves,
  // then give Flutter a beat to attach before typing.
  try {
    await expect(field).toBeFocused({ timeout: 1500 });
  } catch {
    await field.click();
    await expect(field).toBeFocused();
  }
  await page.waitForTimeout(400);
  for (let attempt = 0; attempt < 5; attempt++) {
    await page.keyboard.press('Control+A');
    await page.keyboard.type(text, { delay: 8 });
    await page.waitForTimeout(300);
    if ((await field.inputValue().catch(() => text)) === text) return;
    await field.click();
    await page.waitForTimeout(400);
  }
  throw new Error(`could not type into "${name}"`);
}

const button = (page: Page, name: string | RegExp) =>
  page.getByRole('button', { name, exact: typeof name === 'string' });

async function signup(page: Page, username: string) {
  const email = emailFor(username);
  await page.goto('/');
  await button(page, 'Create an account').click();
  await fill(page, 'Email address', email);
  await button(page, 'Send me a code').click();
  await fill(page, 'Verification code', await codeFor(email));
  await button(page, 'Verify').click();
  await fill(page, 'Username', username);
  await fill(page, 'Password', PASSWORD);
  await fill(page, 'Repeat password', PASSWORD);
  await button(page, 'Create account').click();
  // The first device of a new account is shown its recovery key exactly once and must confirm it
  // was saved before going on.
  await expect(page.getByText('Save your recovery key').first()).toBeVisible();
  await page.getByRole('checkbox', { name: 'I have saved my recovery key' }).click();
  await button(page, 'Continue').click();
  // Signed in: the home screen shows the empty state.
  await expect(page.getByText('No conversations yet').first()).toBeVisible();
}

async function newUser(browser: Browser, label: string): Promise<{ ctx: BrowserContext; page: Page; name: string }> {
  const name = `e2e${label}${Math.random().toString(36).slice(2, 8)}`;
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  openPages.push({ who: label, page });
  page.on('pageerror', (e) => console.log(`[${label}] PAGE ERROR: ${e.message}`));
  const origin = new URL(process.env.E2E_URL ?? 'http://127.0.0.1:18090').host;
  page.on('request', (r) => {
    const u = new URL(r.url());
    if (u.protocol.startsWith('http') && u.host !== origin) foreignRequests.push(`${label}: ${u.host}`);
  });
  if (process.env.E2E_DEBUG) {
    // Frame TYPES only, never contents.
    const kind = (d: string | Buffer) => { try { return JSON.parse(d.toString()).t; } catch { return '?'; } };
    page.on('websocket', (ws) => {
      ws.on('framesent', (f) => console.log(`[${label}] ws ->`, kind(f.payload)));
      ws.on('framereceived', (f) => console.log(`[${label}] ws <-`, kind(f.payload)));
    });
    page.on('console', (m) => { if (m.type() === 'error') console.log(`[${label}] console error: ${m.text()}`); });
  }
  await signup(page, name);
  return { ctx, page, name };
}

test('two people chat end to end, with live typing', async ({ browser }) => {
  const alice = await newUser(browser, 'alice');
  const bob = await newUser(browser, 'bob');

  // Alice starts a chat with Bob.
  await button(alice.page, /New chat/).click();
  await fill(alice.page, 'Their username', bob.name);
  await button(alice.page, 'Start chat').click();
  await expect(alice.page.getByRole('textbox', { name: `Message ${bob.name}` })).toBeVisible();

  // Bob sees a message request, not an open chat.
  await expect(bob.page.getByText('Message requests')).toBeVisible();
  await expect(bob.page.getByRole('button', { name: new RegExp(`${alice.name} wants to chat with you`) })).toBeVisible();

  // Alice sends a first message while it is still a request.
  await fill(alice.page, `Message ${bob.name}`, 'hello bob, it is alice');
  await alice.page.keyboard.press('Enter');
  await expect(alice.page.getByLabel('You said: hello bob, it is alice')).toBeVisible();
  await expect(bob.page.getByRole('button', { name: /hello bob, it is alice/ })).toBeVisible();

  // Bob opens the request and accepts.
  await bob.page.getByRole('button', { name: /hello bob, it is alice/ }).first().click();
  await button(bob.page, 'Accept').click();
  await expect(bob.page.getByRole('textbox', { name: `Message ${alice.name}` })).toBeEnabled();

  // LIVE TYPING: Alice types slowly; Bob sees the draft before it is sent.
  const aliceBox = alice.page.getByRole('textbox', { name: `Message ${bob.name}` });
  await aliceBox.click();
  await alice.page.keyboard.type('are you the', { delay: 60 });
  if (process.env.E2E_DEBUG) {
    await bob.page.waitForTimeout(1500);
    const snap = await bob.page.locator('body').ariaSnapshot();
    console.log('[bob] tree while Alice types:\n' + snap.split('\n').filter((l) => /typing|draft|are you|They said|alice/i.test(l)).join('\n'));
  }
  await expect(bob.page.getByText(`${alice.name} is typing: are you the`).first()).toBeVisible();
  await alice.page.keyboard.type('re?', { delay: 60 });
  await expect(bob.page.getByText(`${alice.name} is typing: are you there?`).first()).toBeVisible();

  // Sending clears the draft and delivers the real message.
  await alice.page.keyboard.press('Enter');
  await expect(bob.page.getByText(/is typing/)).toHaveCount(0);
  await expect(bob.page.getByLabel('They said: are you there?')).toBeVisible();

  // Bob replies.
  await fill(bob.page, `Message ${alice.name}`, 'yes, loud and clear');
  await bob.page.keyboard.press('Enter');
  await expect(alice.page.getByLabel('They said: yes, loud and clear')).toBeVisible();

  // Alice reloads the page: she is still logged in and her history is still there.
  await alice.page.reload();
  await expect(alice.page.getByText(bob.name).first()).toBeVisible();
  await alice.page.getByText(bob.name).first().click();
  await expect(alice.page.getByLabel('You said: are you there?')).toBeVisible();
  await expect(alice.page.getByLabel('They said: yes, loud and clear')).toBeVisible();

  expect(foreignRequests, 'the app must never contact a third party').toEqual([]);
  await alice.ctx.close();
  await bob.ctx.close();
});

test('a wrong password is refused and the page never contacts a third party', async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const origin = new URL(process.env.E2E_URL ?? 'http://127.0.0.1:18090').host;
  const foreign = new Set<string>();
  page.on('request', (r) => {
    const u = new URL(r.url());
    if (u.protocol.startsWith('http') && u.host !== origin) foreign.add(u.host);
  });

  await page.goto('/');
  await fill(page, 'Username', 'nobody_here');
  await fill(page, 'Password', 'whatever password');
  await button(page, 'Log in').click();
  await expect(page.getByText('Wrong username or password').first()).toBeVisible();
  expect([...foreign]).toEqual([]);
  await ctx.close();
});

test('emoji and non-Latin scripts render from our own fonts, never from a third party', async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const origin = new URL(process.env.E2E_URL ?? 'http://127.0.0.1:18090').host;
  const foreign = new Set<string>();
  const fontStatuses: number[] = [];
  const cspErrors: string[] = [];
  page.on('request', (r) => {
    const u = new URL(r.url());
    if (u.protocol.startsWith('http') && u.host !== origin) foreign.add(u.host);
  });
  page.on('response', (r) => {
    if (r.url().includes('/fonts/s/')) fontStatuses.push(r.status());
  });
  page.on('console', (m) => {
    if (/Content Security Policy|violates/.test(m.text())) cspErrors.push(m.text().slice(0, 140));
  });

  await page.goto('/');
  await button(page, 'Log in').waitFor();
  await page.getByRole('textbox', { name: 'Username', exact: true }).click();
  // Emoji, CJK, Korean, Arabic, Hebrew, Thai, Devanagari: none are in the bundled base font.
  await page.keyboard.insertText('😀🎉👋 你好 こんにちは 안녕 مرحبا שלום สวัสดี नमस्ते');
  // The engine fetches the glyph slices it needs, lazily, from our server.
  await expect.poll(() => fontStatuses.length, { timeout: 15_000 }).toBeGreaterThan(3);
  expect(fontStatuses.every((s) => s === 200), `font statuses: ${fontStatuses}`).toBe(true);
  expect([...foreign]).toEqual([]);
  expect(cspErrors).toEqual([]);
  await ctx.close();
});

test('a photo and a file are sent through the browser, shown inline / downloadable, with no policy violations', async ({ browser }) => {
  const alice = await newUser(browser, 'alice');
  const bob = await newUser(browser, 'bob');
  const cspErrors: string[] = [];
  for (const u of [alice, bob]) {
    u.page.on('console', (m) => { if (/Content Security Policy|violates/.test(m.text())) cspErrors.push(m.text().slice(0, 160)); });
  }

  // An accepted conversation (same steps as the chat test).
  await button(alice.page, /New chat/).click();
  await fill(alice.page, 'Their username', bob.name);
  await button(alice.page, 'Start chat').click();
  await fill(alice.page, `Message ${bob.name}`, 'hi');
  await alice.page.keyboard.press('Enter');
  await bob.page.getByRole('button', { name: /hi/ }).first().click();
  await button(bob.page, 'Accept').click();
  await expect(bob.page.getByRole('textbox', { name: `Message ${alice.name}` })).toBeEnabled();

  // A real 4x4 PNG (so the browser can decode and show it) and a small text file.
  const png = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAIAAAAmkwkpAAAAFElEQVR4nGP4z8DAAMb//0MZBDkA+EkT7YP5CsUAAAAASUVORK5CYII=', 'base64');
  const note = Buffer.from('meet at noon — bring the plans');

  async function attach(page: Page, name: string, mimeType: string, buffer: Buffer, caption: string) {
    const chooser = page.waitForEvent('filechooser');
    await button(page, 'Attach a photo, video or file').click();
    await (await chooser).setFiles({ name, mimeType, buffer });
    await expect(page.getByText(`Send to`).first()).toBeVisible();
    await expect(page.getByText(name).first()).toBeVisible();
    await page.getByRole('textbox', { name: 'Caption (optional)' }).fill(caption);
    await button(page, 'Send').click();
  }

  await attach(alice.page, 'pixel.png', 'image/png', png, 'look at this');
  await expect(bob.page.getByLabel('They said: look at this')).toBeVisible();
  // The photo is shown inline (decrypted in the browser).
  await expect(bob.page.getByLabel('Photo pixel.png')).toBeVisible();

  await attach(alice.page, 'notes.txt', 'text/plain', note, 'and the notes');
  await expect(bob.page.getByLabel('They said: and the notes')).toBeVisible();

  // Bob saves the file: what he downloads is exactly what Alice picked.
  const download = bob.page.waitForEvent('download');
  await bob.page.getByRole('button', { name: new RegExp(`File notes.txt, ${note.length} B`) }).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toBe('notes.txt');
  const path = await saved.path();
  expect(require('node:fs').readFileSync(path).equals(note)).toBe(true);

  // Alice sees her own sent file too, and the chat list shows what the last message was.
  await expect(alice.page.getByLabel('Photo pixel.png')).toBeVisible();
  expect(cspErrors).toEqual([]);
  expect(foreignRequests, 'the app must never contact a third party').toEqual([]);
  await alice.ctx.close();
  await bob.ctx.close();
});
