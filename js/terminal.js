/*
 * terminal.js
 *
 * - Drives the typewriter animation on every page.
 * - Intercepts internal link clicks and runs a `clear` command + fade-out
 *   before navigating, so navigation feels like one continuous terminal session.
 * - Adds copy-to-clipboard buttons to every <pre> inside an .article-body.
 * - Adds permalink anchors to <h2>/<h3> inside .article-body.
 * - Makes the chrome traffic lights functional (close / minimize / maximize).
 * - Turns the trailing caret into a real prompt: help, ls, cd, cat, sudo, …
 * - Computes reading time from article word count.
 * - Auto-fills [data-year] spans in the footer.
 * - Auto-fills [data-modified-date] spans with today's date (YYYY/MM/DD)
 *   for the about-page Sigma rule's `modified:` field.
 * - Auto-fills [data-role-duration] spans with elapsed tenure since their
 *   data-since month ("(10m)", "(1yr 3m)") for the about-page rule's
 *   current role.
 *
 * The animation runner reads from the DOM:
 *   <section class="shell">
 *     <div class="block" data-cmd="..." data-after="next-id">
 *       <span class="cmd"></span>                <-- typed into
 *       <div class="output" hidden>...</div>     <-- shown after typing
 *     </div>
 *     ...
 *   </section>
 *
 * A noscript fallback in each page restores [hidden] visibility, and the
 * .cmd spans hold their command text directly so the page is still readable
 * with JS disabled. runShell() clears that text before typing.
 */
(function () {
  'use strict';

  /* --------- timing knobs --------- */
  const PER_CHAR_MS         = 56;
  const PAUSE_AFTER_CMD_MS  = 256;
  const PAUSE_AFTER_OUTPUT_MS = 336;
  const TRANSITION_PAUSE_MS = 176;
  const TRANSITION_FADE_MS  = 176;

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  function prefersReducedMotion() {
    return window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  /* ============================================================
     Typewriter primitives
     ============================================================ */
  async function typeInto(target, text) {
    const caret = document.createElement('span');
    caret.className = 'caret';
    target.insertAdjacentElement('afterend', caret);

    for (let i = 0; i < text.length; i++) {
      target.append(text[i]);
      await wait(PER_CHAR_MS);
    }
    caret.remove();
  }

  function revealById(id) {
    if (!id) return;
    const el = document.getElementById(id);
    if (el) el.hidden = false;
  }

  function showOutput(block) {
    const out = block.querySelector('.output');
    if (out) out.hidden = false;
  }

  /* ============================================================
     Per-page animation
     ============================================================ */
  async function runShell() {
    const blocks = Array.from(document.querySelectorAll('.shell .block'));

    if (prefersReducedMotion()) {
      for (const b of blocks) {
        b.hidden = false;
        const cmd = b.querySelector('.cmd');
        const tgt = b.querySelector('.target');
        if (cmd) cmd.textContent = b.dataset.cmd || cmd.textContent || '';
        if (tgt) tgt.textContent = b.dataset.target || tgt.textContent || '';
        showOutput(b);
      }
      return;
    }

    for (let i = 0; i < blocks.length; i++) {
      const block    = blocks[i];
      const cmdEl    = block.querySelector('.cmd');
      const targetEl = block.querySelector('.target');
      const text     = block.dataset.cmd || '';
      const tgtText  = block.dataset.target || '';
      const nextId   = block.dataset.after;

      // Clear both spans up front. Noscript fallback puts the literal command
      // text inside each span; without this, the target would be visible
      // while the verb is still being typed.
      if (cmdEl)    cmdEl.textContent = '';
      if (targetEl) targetEl.textContent = '';

      if (cmdEl && text) {
        await typeInto(cmdEl, text);
      }
      if (targetEl && tgtText) {
        await typeInto(targetEl, tgtText);
      }
      if ((cmdEl && text) || (targetEl && tgtText)) {
        await wait(PAUSE_AFTER_CMD_MS);
      }
      showOutput(block);
      await wait(PAUSE_AFTER_OUTPUT_MS);
      revealById(nextId);
    }
  }

  /* ============================================================
     Copy-to-clipboard — every <pre> inside .article-body gets a
     small `copy` button. ES|QL and Sigma YAML are the point of
     this site; readers will copy them.
     ============================================================ */
  function setupCopyButtons() {
    const pres = document.querySelectorAll('.article-body pre');
    pres.forEach((pre) => {
      /* The button lives in a non-scrolling wrapper beside the <pre>, not
         inside it. An absolutely positioned child of a scroll container is
         laid out against the unscrolled padding box and then scrolls with
         the content, so a button inside the <pre> slides out of the corner
         as soon as the reader scrolls a wide command line sideways.
         Keeping it in the wrapper pins it to the visible top-right corner. */
      const wrap = document.createElement('div');
      wrap.className = 'code-wrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);

      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.textContent = 'copy';
      btn.setAttribute('aria-label', 'copy code to clipboard');
      btn.addEventListener('click', async () => {
        const code = pre.querySelector('code') || pre;
        const text = (code.innerText || code.textContent || '').replace(/\s+$/, '');
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
          } else {
            // legacy fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
          }
          btn.textContent = 'copied';
          btn.classList.add('is-copied');
        } catch (_) {
          btn.textContent = 'err';
        }
        setTimeout(() => {
          btn.textContent = 'copy';
          btn.classList.remove('is-copied');
        }, 1500);
      });
      wrap.appendChild(btn);
    });
  }

  /* ============================================================
     Anchor permalinks — auto-id any h2/h3 inside .article-body
     and append a clickable `#` that scrolls to it.
     ============================================================ */
  function slugify(s) {
    return s.toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  function addAnchorLinks() {
    const headings = document.querySelectorAll('.article-body h2, .article-body h3');
    headings.forEach((h) => {
      if (!h.id) {
        const slug = slugify(h.textContent || '');
        if (slug) h.id = slug;
      }
      if (!h.id) return;
      const a = document.createElement('a');
      a.className = 'anchor-link';
      a.href = '#' + h.id;
      a.textContent = '#';
      a.setAttribute('aria-label', 'permalink to ' + (h.textContent || '').trim());
      h.appendChild(a);
    });
  }

  /* ============================================================
     Footer year — fill every [data-year] span with the current year.
     ============================================================ */
  function setYear() {
    const year = new Date().getFullYear();
    document.querySelectorAll('[data-year]').forEach((el) => {
      el.textContent = year;
    });
  }

  /* ============================================================
     Profile rule — fill every [data-modified-date] span with today
     in Sigma's date format (YYYY/MM/DD). Used on /about/ to keep
     the rule's `modified:` field current on every load.
     ============================================================ */
  function setModifiedDate() {
    const now = new Date();
    const y  = now.getFullYear();
    const m  = String(now.getMonth() + 1).padStart(2, '0');
    const d  = String(now.getDate()).padStart(2, '0');
    const stamp = y + '/' + m + '/' + d;
    document.querySelectorAll('[data-modified-date]').forEach((el) => {
      el.textContent = stamp;
    });
  }

  /* ============================================================
     Profile rule — fill every [data-role-duration] span with the
     elapsed time since its data-since month (YYYY-MM), formatted
     "(10m)" / "(1yr)" / "(1yr 3m)". Used on /about/ to keep the
     current role's tenure accurate on every load.
     ============================================================ */
  function setRoleDuration() {
    const now = new Date();
    document.querySelectorAll('[data-role-duration]').forEach((el) => {
      const parts = (el.getAttribute('data-since') || '').split('-');
      if (parts.length !== 2) return;
      /* LinkedIn-style inclusive count — both endpoint months count,
         so a role started this month reads (1m). */
      const months = (now.getFullYear() - Number(parts[0])) * 12 +
                     (now.getMonth() + 1 - Number(parts[1])) + 1;
      if (months < 1 || Number.isNaN(months)) return;
      const yr = Math.floor(months / 12);
      const mo = months % 12;
      let label;
      if (yr === 0)      label = mo + 'm';
      else if (mo === 0) label = yr + 'yr';
      else               label = yr + 'yr ' + mo + 'm';
      el.textContent = '(' + label + ')';
    });
  }

  /* ============================================================
     Page transition — animate `clear` then navigate.
     ============================================================ */
  let transitionRunning = false;

  function currentDir() {
    const dirEls = document.querySelectorAll('.line .dir');
    if (dirEls.length) return dirEls[dirEls.length - 1].textContent || '~';
    const ct = document.querySelector('.chrome-title');
    if (ct) {
      const m = ct.textContent.match(/:(~[^\s]*)$/);
      if (m) return m[1];
    }
    return '~';
  }

  function buildPromptLine(dir) {
    const line = document.createElement('div');
    line.className = 'line';
    line.innerHTML =
      '<span class="ps1">' +
        '<span class="user">josh</span>' +
        '<span class="sep">@</span>' +
        '<span class="user">kiriakoff</span>' +
        '<span class="sep">:</span>' +
        '<span class="dir"></span>' +
        '<span class="sep">$</span>' +
      '</span><span class="cmd transition-cmd"></span>';
    line.querySelector('.dir').textContent = dir;
    return line;
  }

  async function navigateWithClear(url) {
    if (transitionRunning) return;
    transitionRunning = true;

    if (prefersReducedMotion()) {
      window.location.href = url;
      return;
    }

    const shell = document.querySelector('.shell');
    if (!shell) {
      window.location.href = url;
      return;
    }

    document.querySelectorAll('.caret').forEach((c) => c.remove());

    const promptLine = buildPromptLine(currentDir());
    shell.appendChild(promptLine);
    promptLine.scrollIntoView({ behavior: 'smooth', block: 'end' });

    const target = promptLine.querySelector('.transition-cmd');
    await typeInto(target, 'clear');
    await wait(TRANSITION_PAUSE_MS);

    document.body.classList.add('fading-out');
    await wait(TRANSITION_FADE_MS);

    window.location.href = url;
  }

  /* ============================================================
     Click interceptor
     ============================================================ */
  function isInternalNavLink(a) {
    if (!a) return false;
    if (a.target === '_blank') return false;
    if (a.hasAttribute('download')) return false;

    const href = a.getAttribute('href');
    if (!href) return false;
    if (href.startsWith('#'))           return false;
    if (href.startsWith('mailto:'))     return false;
    if (href.startsWith('tel:'))        return false;
    if (href.startsWith('javascript:')) return false;

    if (/^[a-z]+:\/\//i.test(href)) {
      try {
        const u = new URL(href);
        return u.origin === window.location.origin;
      } catch (_) {
        return false;
      }
    }
    return true;
  }

  function setupNavigation() {
    document.addEventListener('click', (e) => {
      if (e.defaultPrevented) return;
      if (e.button !== 0) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

      const a = e.target.closest('a');
      if (!isInternalNavLink(a)) return;

      e.preventDefault();
      navigateWithClear(a.href);
    });
  }

  /* ============================================================
     Window controls — the chrome traffic lights are functional.
     JS swaps the decorative spans for real <button>s at boot, so
     the noscript page keeps its plain dots. Close hides the window
     behind an ssh-style reconnect line; min collapses the window
     to its title bar; max stretches it to the full viewport.
     ============================================================ */
  let windowClosed = false;

  function ensureReconnectUI() {
    let wrap = document.querySelector('.reconnect');
    if (wrap) return wrap;
    wrap = document.createElement('div');
    wrap.className = 'reconnect';
    const inner = document.createElement('div');
    inner.className = 'reconnect-inner';
    const msg = document.createElement('div');
    msg.textContent = 'Connection to kiriakoff closed.';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'reconnect-btn';
    btn.textContent = '$ ssh josh@kiriakoff';
    btn.addEventListener('click', reopenWindow);
    inner.append(msg, btn);
    wrap.appendChild(inner);
    document.body.appendChild(wrap);
    return wrap;
  }

  async function closeWindow() {
    const win = document.querySelector('.window');
    if (!win || windowClosed) return;
    windowClosed = true;
    ensureReconnectUI();
    if (!prefersReducedMotion()) {
      win.classList.add('is-closing');
      await wait(190);
    }
    win.classList.remove('is-closing');
    document.body.classList.add('win-closed');
    const btn = document.querySelector('.reconnect-btn');
    if (btn) btn.focus();
  }

  function reopenWindow() {
    if (!windowClosed) return;
    windowClosed = false;
    document.body.classList.remove('win-closed');
    const close = document.querySelector('.lights .l-close');
    if (close && close.focus) close.focus();
  }

  function setupWindowControls() {
    const lights = document.querySelector('.lights');
    const win = document.querySelector('.window');
    if (!lights || !win) return;

    lights.removeAttribute('aria-hidden');

    const controls = [
      ['l-close', 'close window', () => { closeWindow(); }],
      ['l-min', 'minimize window', (btn) => {
        const on = win.classList.toggle('is-min');
        btn.setAttribute('aria-pressed', String(on));
      }],
      ['l-max', 'maximize window', (btn) => {
        const on = win.classList.toggle('is-max');
        btn.setAttribute('aria-pressed', String(on));
      }],
    ];

    controls.forEach(([cls, label, onClick]) => {
      const dot = lights.querySelector('.' + cls);
      if (!dot) return;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = cls;
      btn.title = label;
      btn.setAttribute('aria-label', label);
      if (cls !== 'l-close') btn.setAttribute('aria-pressed', 'false');
      btn.addEventListener('click', () => onClick(btn));
      dot.replaceWith(btn);
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && windowClosed) reopenWindow();
    });
  }

  /* ============================================================
     Interactive prompt — the trailing caret on every page accepts
     real input. A visually-hidden <input> captures keystrokes and
     a .cmd span mirrors them; Enter freezes the line into the
     scrollback and appends output, shaped exactly like the
     animated blocks so existing shell CSS covers everything.
     ============================================================ */
  const CMD_LIST = ['cat', 'cd', 'clear', 'echo', 'exit', 'help', 'history', 'ls', 'pwd', 'sudo', 'whoami'];

  /* One VFS node per real page. `entries` mirror what the page
     trees advertise; `hidden` only shows under `ls -a`. */
  const VFS = {
    '~':                           { entries: ['about/', 'blog/', 'detections/', 'intel/', 'recent.md'], hidden: ['.links/', 'admin/'] },
    '~/about':                     { entries: ['win_susp_net_user_add_quiet.yml'], hidden: [] },
    '~/blog':                      { entries: ['clickfix-donut-chain/', 'README.md', 'DISCLAIMER'], hidden: [] },
    '~/blog/clickfix-donut-chain': { entries: ['lets-clickfix-some-errors.md'], hidden: [] },
    '~/detections':                { entries: ['vssadmin-resize-shadowstorage/', 'privileged-group-member-added/', 'netsh-legacy-firewall-remote/', 'reg-misspelled-controlset/', 'signed-invalid-dll-user-path/', 'macsync-implant-macos/', 'system-dll-name-non-system-path/', 'unsigned-dll-system-binary/', 'cipher-wipe-free-space/', 'komari-agent-c2/', 'msiexec-vrf-temp-installer/', 'example/', 'klist-ticket-cache-purge/', 'vendor-branded-user-path/', 'reg-import-user-writable/', 'renamed-lolbin-originalfilename/', 'README.md'], hidden: [] },
    '~/detections/example':        { entries: ['example.md'], hidden: [] },
    '~/detections/reg-misspelled-controlset': { entries: ['reg-misspelled-controlset.md'], hidden: [] },
    '~/detections/msiexec-vrf-temp-installer': { entries: ['msiexec-vrf-temp-installer.md'], hidden: [] },
    '~/detections/reg-import-user-writable': { entries: ['reg-import-user-writable.md'], hidden: [] },
    '~/detections/netsh-legacy-firewall-remote': { entries: ['netsh-legacy-firewall-remote.md'], hidden: [] },
    '~/detections/cipher-wipe-free-space': { entries: ['cipher-wipe-free-space.md'], hidden: [] },
    '~/detections/komari-agent-c2':       { entries: ['komari-agent-c2.md'], hidden: [] },
    '~/detections/macsync-implant-macos': { entries: ['macsync-implant-macos.md'], hidden: [] },
    '~/detections/unsigned-dll-system-binary': { entries: ['unsigned-dll-system-binary.md'], hidden: [] },
    '~/detections/system-dll-name-non-system-path': { entries: ['system-dll-name-non-system-path.md'], hidden: [] },
    '~/detections/signed-invalid-dll-user-path': { entries: ['signed-invalid-dll-user-path.md'], hidden: [] },
    '~/detections/vendor-branded-user-path': { entries: ['vendor-branded-user-path.md'], hidden: [] },
    '~/detections/renamed-lolbin-originalfilename': { entries: ['renamed-lolbin-originalfilename.md'], hidden: [] },
    '~/detections/klist-ticket-cache-purge': { entries: ['klist-ticket-cache-purge.md'], hidden: [] },
    '~/detections/vssadmin-resize-shadowstorage': { entries: ['vssadmin-resize-shadowstorage.md'], hidden: [] },
    '~/detections/privileged-group-member-added': { entries: ['privileged-group-member-added.md'], hidden: [] },
    '~/intel':                     { entries: ['README.md', 'intel.log', 'feed.json'], hidden: [] },
    '~/admin':                     { entries: [], hidden: [] },
  };

  function normalizePath(cwd, arg) {
    if (!arg || arg === '~' || arg === '~/') return '~';
    let parts;
    if (arg.startsWith('~/')) {
      parts = arg.slice(2).split('/');
    } else if (arg.startsWith('/')) {
      parts = arg.replace(/^\/home\/josh\/?/, '').split('/');
    } else {
      parts = cwd === '~' ? [] : cwd.slice(2).split('/');
      parts = parts.concat(arg.split('/'));
    }
    const out = [];
    for (const p of parts) {
      if (p === '' || p === '.') continue;
      if (p === '..') { out.pop(); continue; }
      out.push(p);
    }
    return out.length ? '~/' + out.join('/') : '~';
  }

  function pathToUrl(cwd, path) {
    const depth = cwd === '~' ? 0 : cwd.slice(2).split('/').length;
    const up = '../'.repeat(depth);
    if (path === '~') return up || './';
    return (up || './') + path.slice(2) + '/';
  }

  function setupInteractivePrompt() {
    /* The prompt only accepts input on the home and about pages.
       Article pages (blog, detections) keep their trailing caret
       purely decorative — no input, no key capture. */
    const active = document.querySelector('.tabs a.active');
    const section = active ? active.textContent.trim() : '';
    if (section !== 'josh.kiriakoff' && section !== 'about') return;

    const shell = document.querySelector('.shell');
    if (!shell) return;
    const blocks = shell.querySelectorAll('.block');
    if (!blocks.length) return;
    const liveBlock = blocks[blocks.length - 1];
    const liveLine = liveBlock.querySelector('.line');
    const caret = liveLine && liveLine.querySelector('.caret');
    if (!liveLine || !caret) return;

    const cwd = currentDir();

    const echoSpan = document.createElement('span');
    echoSpan.className = 'cmd live-cmd';
    caret.insertAdjacentElement('beforebegin', echoSpan);

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'term-input';
    input.setAttribute('aria-label', 'terminal command input — type help and press enter');
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('autocomplete', 'off');
    input.setAttribute('autocorrect', 'off');
    input.spellcheck = false;
    liveLine.classList.add('live-line');
    liveLine.appendChild(input);

    const hist = [];
    let histIdx = -1;

    function setValue(v) {
      input.value = v;
      echoSpan.textContent = v;
    }

    function scrollToPrompt() {
      liveLine.scrollIntoView({
        behavior: prefersReducedMotion() ? 'auto' : 'smooth',
        block: 'nearest',
      });
    }

    /* freeze the typed command into the scrollback as a static block */
    function freezeLine(text) {
      const b = document.createElement('div');
      b.className = 'block';
      const line = buildPromptLine(cwd);
      const cmdEl = line.querySelector('.cmd');
      cmdEl.className = 'cmd';
      cmdEl.textContent = text;
      b.appendChild(line);
      shell.insertBefore(b, liveBlock);
      return b;
    }

    function print(block, text) {
      const out = document.createElement('div');
      out.className = 'output';
      out.textContent = text;
      block.appendChild(out);
      return out;
    }

    function printPre(block, text) {
      const out = document.createElement('div');
      out.className = 'output';
      const pre = document.createElement('pre');
      pre.className = 'tree';
      pre.textContent = text;
      out.appendChild(pre);
      block.appendChild(out);
      return out;
    }

    function doHelp(block) {
      printPre(block,
        'cat <file>     print a file to the terminal\n' +
        'cd <dir>       change directory (this navigates)\n' +
        'clear          wipe the scrollback\n' +
        'echo <text>    write arguments to output\n' +
        'exit           close the window\n' +
        'help           this text\n' +
        'history        list commands from this session\n' +
        'ls [-a]        list directory contents\n' +
        'pwd            print working directory\n' +
        'sudo <cmd>     execute a command as root\n' +
        'whoami         print the current user\n' +
        '\n' +
        'tab completes commands and paths; up/down walk history.');
    }

    function doLs(block, argv) {
      const showAll = argv.includes('-a');
      const targetArg = argv.slice(1).find((a) => !a.startsWith('-'));
      const path = targetArg ? normalizePath(cwd, targetArg) : cwd;
      const node = VFS[path];
      if (!node) {
        print(block, "ls: cannot access '" + targetArg + "': No such file or directory")
          .classList.add('shell-error');
        return;
      }
      const names = (showAll ? ['./', '../'].concat(node.hidden) : []).concat(node.entries);
      if (!names.length) return;
      const out = document.createElement('div');
      out.className = 'output';
      const pre = document.createElement('pre');
      pre.className = 'tree';
      names.forEach((n, i) => {
        if (i) pre.append('  ');
        if (n.endsWith('/')) {
          const s = document.createElement('span');
          s.className = 'd';
          s.textContent = n;
          pre.appendChild(s);
        } else {
          pre.append(n);
        }
      });
      out.appendChild(pre);
      block.appendChild(out);
    }

    function doHistory(block) {
      if (!hist.length) return;
      printPre(block, hist.map((h, i) => String(i + 1).padStart(3, ' ') + '  ' + h).join('\n'));
    }

    function doClear() {
      Array.from(shell.children).forEach((el) => {
        if (el !== liveBlock) el.remove();
      });
    }

    function doCat(block, name) {
      if (!name) {
        print(block, 'usage: cat <file>');
        return;
      }
      const norm = name.replace(/^\.\//, '').replace(/^~\//, '');
      const src = Array.from(document.querySelectorAll('.shell .block[data-target]')).find((b) => {
        const t = (b.dataset.target || '').replace(/^\.\//, '').replace(/^~\//, '');
        return t === norm;
      });
      if (src) {
        const srcOut = src.querySelector('.output');
        if (srcOut) {
          const out = document.createElement('div');
          out.className = 'output';
          out.innerHTML = srcOut.innerHTML;
          block.appendChild(out);
          return;
        }
      }
      if (VFS[normalizePath(cwd, name)]) {
        print(block, 'cat: ' + name + ': Is a directory').classList.add('shell-error');
        return;
      }
      const node = VFS[cwd];
      if (node && node.entries.includes(norm)) {
        print(block, 'cat: ' + norm + ': already on your screen — scroll up');
        return;
      }
      print(block, 'cat: ' + name + ': No such file or directory').classList.add('shell-error');
    }

    function doCd(block, target) {
      const dest = normalizePath(cwd, target || '~');
      if (dest === '~/.links') {
        print(block, 'bash: cd: .links: Permission denied').classList.add('shell-error');
        return false;
      }
      if (dest === cwd) return false;
      if (VFS[dest]) {
        navigateWithClear(pathToUrl(cwd, dest));
        return true;
      }
      const parent = VFS[dest.split('/').slice(0, -1).join('/') || '~'] || VFS['~'];
      const base = dest.split('/').pop();
      const isFile = parent && parent.entries.some((e) => e === base);
      print(block, 'bash: cd: ' + (target || '~') + ': ' +
        (isFile ? 'Not a directory' : 'No such file or directory'))
        .classList.add('shell-error');
      return false;
    }

    function doSudo(block) {
      print(block, 'josh is not in the sudoers file.  This incident will be reported.')
        .classList.add('shell-error');
      const now = new Date();
      const stamp = now.getFullYear() + '-' +
        String(now.getMonth() + 1).padStart(2, '0') + '-' +
        String(now.getDate()).padStart(2, '0');
      const out = document.createElement('div');
      out.className = 'output';
      out.append('report written to ');
      const a = document.createElement('a');
      a.href = pathToUrl(cwd, '~/detections');
      a.textContent = '~/detections/incident-' + stamp + '.md';
      out.appendChild(a);
      block.appendChild(out);
    }

    function complete() {
      const val = input.value;
      const tokens = val.split(/\s+/).filter(Boolean);
      const completingFirst = tokens.length <= 1 && !/\s$/.test(val);
      const prefix = /\s$/.test(val) ? '' : (tokens[tokens.length - 1] || '');
      const node = VFS[cwd] || { entries: [], hidden: [] };
      const candidates = completingFirst
        ? CMD_LIST.slice()
        : node.entries.concat(node.hidden);
      const matches = candidates.filter((c) => c.startsWith(prefix));
      if (!matches.length) return;

      let lcp = matches[0];
      for (const m of matches) {
        while (!m.startsWith(lcp)) lcp = lcp.slice(0, -1);
      }
      if (matches.length === 1) {
        const done = matches[0] + (matches[0].endsWith('/') ? '' : ' ');
        setValue(val.slice(0, val.length - prefix.length) + done);
      } else if (lcp.length > prefix.length) {
        setValue(val.slice(0, val.length - prefix.length) + lcp);
      } else {
        const b = freezeLine(val);
        printPre(b, matches.join('  '));
        scrollToPrompt();
      }
    }

    function run(raw) {
      if (transitionRunning || windowClosed) return;
      const trimmed = raw.trim();
      setValue('');
      histIdx = -1;

      const block = freezeLine(raw);

      if (!trimmed) {
        scrollToPrompt();
        return;
      }
      hist.push(raw);

      const argv = trimmed.split(/\s+/);
      const cmd = argv[0];

      switch (cmd) {
        case 'help':    doHelp(block); break;
        case 'ls':      doLs(block, argv); break;
        case 'pwd':     print(block, cwd === '~' ? '/home/josh' : '/home/josh/' + cwd.slice(2)); break;
        case 'whoami':  print(block, 'josh'); break;
        case 'echo':    print(block, argv.slice(1).join(' ')); break;
        case 'history': doHistory(block); break;
        case 'clear':   doClear(); return;
        case 'cat':     doCat(block, argv[1]); break;
        case 'cd':      if (doCd(block, argv[1])) return; break;
        case 'exit':    closeWindow(); return;
        case 'sudo':    doSudo(block); break;
        default:
          print(block, 'bash: ' + cmd + ': command not found').classList.add('shell-error');
      }
      scrollToPrompt();
    }

    input.addEventListener('input', () => {
      echoSpan.textContent = input.value;
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        run(input.value);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (!hist.length) return;
        if (histIdx === -1) histIdx = hist.length - 1;
        else if (histIdx > 0) histIdx--;
        setValue(hist[histIdx]);
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (histIdx === -1) return;
        histIdx++;
        if (histIdx >= hist.length) { histIdx = -1; setValue(''); }
        else setValue(hist[histIdx]);
      } else if (e.key === 'Tab') {
        e.preventDefault();
        complete();
      } else if (e.key === 'c' && e.ctrlKey) {
        e.preventDefault();
        freezeLine(input.value + '^C');
        setValue('');
        scrollToPrompt();
      }
    });

    /* click (or start typing) anywhere in the shell to focus the prompt */
    shell.addEventListener('click', (e) => {
      if (e.target.closest('a, button, input, textarea')) return;
      if (window.getSelection && String(window.getSelection())) return;
      input.focus({ preventScroll: true });
    });

    document.addEventListener('keydown', (e) => {
      if (windowClosed || transitionRunning) return;
      if (e.target === input) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' ||
                t.tagName === 'SELECT' || t.isContentEditable)) return;
      /* space stays free for page scrolling */
      if ((e.key.length === 1 && e.key !== ' ') || e.key === 'Backspace') {
        input.focus({ preventScroll: true });
      }
    });
  }

  /* ============================================================
     Boot
     ============================================================ */
  function boot() {
    setYear();
    setModifiedDate();
    setRoleDuration();
    addAnchorLinks();
    setupCopyButtons();
    setupNavigation();
    setupWindowControls();
    runShell().then(setupInteractivePrompt);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
