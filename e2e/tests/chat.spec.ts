import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { readFileSync, existsSync } from 'node:fs';

const MAIL_FILE = process.env.E2E_MAIL_FILE!;
const PASSWORD = 'correct horse battery staple';

/** Any request to a host other than the app's own: there must never be one. */
const foreignRequests: string[] = [];

/** The verification code emailed to `to` (the `already`-th message to that address). */
async function codeFor(to: string, already = 0): Promise<string> {
  for (let i = 0; i < 80; i++) {
    if (existsSync(MAIL_FILE)) {
      const lines = readFileSync(MAIL_FILE, 'utf8').trim().split('\n').filter(Boolean)
        .map((l) => JSON.parse(l)).filter((m) => m.to === to);
      const m = lines[already];
      if (m) return /(\d{6})/.exec(m.subject)![1];
    }
    await new Promise((r) => setTimeout(r, 100));
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
  for (let attempt = 0; attempt < 5; attempt++) {
    await field.click();
    await expect(field).toBeFocused();
    await page.keyboard.press('Control+A');
    await page.keyboard.type(text, { delay: 8 });
    if ((await field.inputValue().catch(() => text)) === text) return;
    await page.waitForTimeout(200);
  }
  throw new Error(`could not type into "${name}"`);
}

const button = (page: Page, name: string | RegExp) =>
  page.getByRole('button', { name, exact: typeof name === 'string' });

async function signup(page: Page, username: string) {
  const email = `${username}@example.test`;
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
  // Signed in: the home screen shows the empty state.
  await expect(page.getByText('No conversations yet').first()).toBeVisible();
}

async function newUser(browser: Browser, label: string): Promise<{ ctx: BrowserContext; page: Page; name: string }> {
  const name = `${label}${Math.random().toString(36).slice(2, 8)}`;
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
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
