const fs = require('node:fs');
const path = require('node:path');
// Install marked separately or set REPORT_MARKED_MODULE to its module path.
// Set REPORT_MERMAID_SCRIPT to a local Mermaid browser bundle before exporting.
const { marked } = require(process.env.REPORT_MARKED_MODULE || 'marked');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '../..');
const output = path.join(root, 'output/pdf');
const scratch = path.join(root, 'tmp/pdfs/report-add');
const escape = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

(async () => {
  if (!process.env.REPORT_MERMAID_SCRIPT) {
    throw new Error('Set REPORT_MERMAID_SCRIPT to a local Mermaid browser bundle.');
  }
  fs.mkdirSync(output, { recursive: true });
  fs.mkdirSync(scratch, { recursive: true });
  let html = marked.parse(fs.readFileSync(path.join(root, 'report-add.md'), 'utf8'));
  html = html.replace(/<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g,
    (_, source) => `<div class="diagram">${source}</div>`);
  html = html.replace(/src="(report-assets\/[^"\n]+)"/g, (_, file) => {
    const data = fs.readFileSync(path.join(root, file)).toString('base64');
    return `src="data:image/png;base64,${data}"`;
  });
  const css = `
    @page { size: A4; margin: 17mm 16mm 18mm; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 10pt/1.48 Arial, sans-serif; color: #203348; }
    h1 { font-size: 23pt; line-height: 1.18; color: #173f73; border-bottom: 2pt solid #237e78; padding-bottom: 12pt; margin: 0 0 20pt; break-before: page; }
    h1:first-child { break-before: auto; }
    h2 { font-size: 15pt; color: #173f73; margin: 22pt 0 10pt; }
    h3 { font-size: 11.5pt; color: #237e78; margin: 16pt 0 8pt; }
    h1,h2,h3 { break-after: avoid; }
    p { margin: 0 0 10pt; orphans: 3; widows: 3; }
    table { width: 100%; border-collapse: collapse; margin: 13pt 0; table-layout: fixed; font-size: 8.1pt; line-height: 1.34; }
    thead { display: table-header-group; }
    th { background: #eaf2f8; color: #173f73; text-align: left; }
    td, th { padding: 6pt; border: .55pt solid #b8c4d1; overflow-wrap: anywhere; vertical-align: top; }
    tr { break-inside: avoid; }
    td:first-child { font-weight: 600; }
    pre { font: 7.1pt/1.42 Consolas, monospace; background: #f3f6fa; padding: 10pt; border-left: 2pt solid #237e78; white-space: pre-wrap; overflow-wrap: anywhere; break-inside: avoid; }
    code { font-family: Consolas, monospace; font-size: .92em; }
    a { color: #173f73; text-decoration: none; }
    li { margin-bottom: 7pt; }
    ol { padding-left: 19pt; }
    .diagram { text-align: center; margin: 15pt 0 8pt; break-inside: avoid; }
    .diagram svg { width: 100%; height: auto; max-height: 220mm; }
    p:has(> em:only-child) { font-size: 8.3pt; line-height: 1.4; color: #536477; }
    img { display: block; max-width: 100%; max-height: 235mm; margin: auto; }
    .screenshot-page { break-before: page; break-after: page; }
    .screenshot-page h4 { color: #173f73; margin: 0 0 10pt; font-size: 12pt; }
    .screenshot-page img { width: 100%; max-height: 226mm; object-fit: contain; }
  `;
  const browser = await chromium.launch({ headless: false });
  try {
    const page = await browser.newPage({ viewport: { width: 1200, height: 1000 }, timezoneId: 'Asia/Kolkata' });
    await page.setContent(`<!doctype html><html><head><meta charset="utf-8"><title>Agent Security MCP Gateway - Chapters 4-7</title><style>${css}</style></head><body>${html}</body></html>`);
    await page.addScriptTag({ path: process.env.REPORT_MERMAID_SCRIPT });
    await page.evaluate(async () => {
      mermaid.initialize({ startOnLoad: false, theme: 'base', securityLevel: 'strict',
        themeVariables: { fontFamily: 'Arial', fontSize: '16px', primaryColor: '#eaf2f8', primaryTextColor: '#203348', primaryBorderColor: '#285a86', lineColor: '#637385', secondaryColor: '#edf6f3', tertiaryColor: '#fff7e8' },
        flowchart: { useMaxWidth: true, htmlLabels: false, curve: 'linear' } });
      await mermaid.run({ querySelector: '.diagram' });
      await document.fonts.ready;
      await Promise.all([...document.images].map(im => im.decode()));
    });
    const diagrams = await page.locator('.diagram svg').count();
    if (diagrams !== 7) throw new Error(`Expected 7 rendered diagrams, got ${diagrams}`);
    // Spread the long real dashboard capture across readable detail panels.
    await page.evaluate(async () => {
      const img = document.querySelector('img');
      const original = img.parentElement;
      const pieces = 3;
      for (let i = 0; i < pieces; i++) {
        const top = Math.floor(i * img.naturalHeight / pieces);
        const bottom = Math.floor((i + 1) * img.naturalHeight / pieces);
        const canvas = document.createElement('canvas');
        const left = 135, right = 130;
        canvas.width = img.naturalWidth - left - right;
        canvas.height = bottom - top;
        canvas.getContext('2d').drawImage(img, left, top, canvas.width, canvas.height, 0, 0, canvas.width, canvas.height);
        const panel = document.createElement('section');
        panel.className = 'screenshot-page';
        const title = document.createElement('h4');
        title.textContent = `Figure 6.2 - Actual prototype dashboard (${i + 1} of ${pieces})`;
        const cropped = new Image(); cropped.src = canvas.toDataURL('image/png');
        panel.append(title, cropped); original.before(panel);
      }
      original.remove();
      await Promise.all([...document.images].map(im => im.decode()));
    });
    fs.writeFileSync(path.join(scratch, 'report-add-rendered.html'), await page.content());
    await page.pdf({ path: path.join(output, 'report-add.pdf'), printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<div style="width:100%;font:8px Arial;color:#637385;padding:0 60px;">AGENT SECURITY MCP GATEWAY | CHAPTERS 4-7</div>',
      footerTemplate: '<div style="width:100%;font:8px Arial;color:#637385;padding:0 60px;display:flex;justify-content:space-between;"><span>Local non-production prototype | 3 October 2026</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>' });
    console.log(`Created report-add.pdf with ${diagrams} embedded diagrams and three screenshot panels.`);
  } finally { await browser.close(); }
})().catch(err => { console.error(err); process.exitCode = 1; });
