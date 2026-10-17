// Open a KeelMap map in headless Chrome and report anything unsafe or broken.
//
//   npm install @sparticuz/chromium@131.0.1 puppeteer-core@23.10.4
//   node tools/check_map_browser.js map.html
//
// Fails (exit 1) on: Content Security Policy violations, console or page errors,
// dialogs, any <img> or extra <script> created from data, or window.__pwned
// being set (the marker used by tools/make_hostile_map.py).
const chromium = require("@sparticuz/chromium");
const pp = require("puppeteer-core");
const path = require("path");

(async () => {
  const file = path.resolve(process.argv[2]);
  const browser = await pp.launch({ executablePath: await chromium.executablePath(), args: chromium.args, headless: true });
  const problems = [];
  for (const scheme of ["light", "dark"]) {
    const page = await browser.newPage();
    await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
    await page.setViewport({ width: 1440, height: 900 });
    page.on("dialog", d => { problems.push(`${scheme}: dialog opened`); d.dismiss(); });
    page.on("pageerror", e => problems.push(`${scheme}: page error ${e.message}`));
    page.on("console", m => { if (m.type() === "error") problems.push(`${scheme}: console ${m.text()}`); });
    await page.evaluateOnNewDocument(() => document.addEventListener("securitypolicyviolation",
      e => { window.__csp = (window.__csp || []).concat(e.violatedDirective); }));
    await page.goto("file://" + file, { waitUntil: "load" });
    await new Promise(r => setTimeout(r, 800));
    // visit every asset and open every evidence list
    const assets = await page.evaluate(() => document.querySelectorAll(".assets button").length);
    for (let i = 0; i < assets; i++) {
      await page.evaluate(i => { document.querySelector(".link")?.click(); document.querySelectorAll(".assets button")[i].click();
        document.querySelectorAll("details").forEach(d => d.open = true); }, i);
    }
    const r = await page.evaluate(() => ({ csp: window.__csp || [], pwned: window.__pwned,
      imgs: document.querySelectorAll("img").length, scripts: document.scripts.length }));
    if (r.csp.length) problems.push(`${scheme}: CSP violations ${r.csp.join(", ")}`);
    if (r.pwned !== undefined) problems.push(`${scheme}: injected script ran`);
    if (r.imgs) problems.push(`${scheme}: ${r.imgs} img elements created`);
    if (r.scripts !== 3) problems.push(`${scheme}: ${r.scripts} script elements, expected 3`);
    console.log(`${scheme}: visited ${assets} assets`);
    await page.close();
  }
  await browser.close();
  if (problems.length) { problems.forEach(p => console.log("PROBLEM", p)); process.exit(1); }
  console.log("OK: no CSP violations, errors, dialogs or injected content");
})().catch(e => { console.error(e); process.exit(1); });
