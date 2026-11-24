// --- CSRF helpers ------------------------------------------------------------
//
// Quick recap of why this file needs to bother with CSRF tokens at all: the server keeps
// you logged in through an httpOnly cookie, which the browser attaches to every request to
// this origin automatically, no questions asked. That's convenient, but it also means a
// completely different website you have open in another tab could make your browser send
// a request here too, riding along on that same cookie. Spring Security's defence is a
// second cookie, XSRF-TOKEN, that JavaScript is allowed to read. On every POST we copy its
// value into an X-XSRF-TOKEN header. A page on some other origin can trigger the cookie,
// but it can never read it to produce that header, so the server can tell our own page
// apart from an impostor.

// Cookies all live together in one semicolon-separated string (document.cookie), there's
// no built-in "give me cookie X" function, so a tiny regex has to do the looking-up.
function getCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

// Calling this GET endpoint is only about its side effect: it makes the server set the
// XSRF-TOKEN cookie. Spring only generates that token lazily, so without this call the
// cookie simply wouldn't exist yet when we need it for the first login attempt.
async function ensureCsrfCookie() {
    const response = await fetch('/api/auth/csrf', { credentials: 'same-origin' });

    if (!response.ok) {
        // If this ever fails, every single login and upload attempt below is going to be
        // rejected for a missing CSRF token, so it's worth shouting about immediately
        // rather than letting it surface later as a confusing login failure.
        console.error(`[CSRF] Could not fetch a CSRF token (status ${response.status}). ` +
            'The XSRF-TOKEN cookie was never set, so every POST on this page will be rejected.');
    }
}

// Spread this into the headers of every POST/PUT/PATCH/DELETE request. GET requests never
// need it, Spring Security only checks CSRF on requests that change something.
function csrfHeaders() {
    return { 'X-XSRF-TOKEN': getCookie('XSRF-TOKEN') };
}

// One place to log a failed request. We read the server's ErrorDTO body ({"error": "..."})
// and print it to the console, calling out CSRF failures specifically since "token is
// missing" and "token is invalid" point at two different bugs: the first usually means
// ensureCsrfCookie() above never ran or was blocked, the second usually means a stale page
// is still using a CSRF cookie value the server has since replaced.
function logRequestFailure(action, response, body) {
    const message = (body && body.error) || `HTTP ${response.status}`;

    if (message.toLowerCase().includes('csrf')) {
        console.warn(`[CSRF] ${action} was rejected: ${message} (status ${response.status}).`);
    } else {
        console.info(`${action} failed: ${message} (status ${response.status}).`);
    }
}

// --- Page elements -------------------------------------------------------------

const loginSection = document.getElementById('login-section');
const appSection = document.getElementById('app-section');
const sessionStatus = document.getElementById('session-status');
const usernameDisplay = document.getElementById('username-display');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const logoutButton = document.getElementById('logout-button');
const uploadForm = document.getElementById('upload-form');
const uploadError = document.getElementById('upload-error');
const fileList = document.getElementById('file-list');

// --- Session ---------------------------------------------------------------------

function showLoggedOut() {
    loginSection.hidden = false;
    appSection.hidden = true;
    sessionStatus.textContent = 'Not logged in';
}

function showLoggedIn(user) {
    loginSection.hidden = true;
    appSection.hidden = false;
    usernameDisplay.textContent = user.username;
    sessionStatus.textContent = `Logged in as ${user.username} (${user.roles.join(', ')})`;
}

// Asks the server "who am I, according to my cookie?" and updates the page to match. We
// call this once on page load, and again right after logging in or out, so the UI is always
// a direct reflection of what the server actually thinks our session is, never guessed.
async function refreshSession() {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' });

    if (response.ok) {
        showLoggedIn(await response.json());
        await loadFiles();
    } else {
        // Perfectly normal on a first visit (nobody's logged in yet), so this is an info
        // log rather than a warning, logRequestFailure only escalates it if the body
        // actually mentions a CSRF problem.
        const body = await response.json().catch(() => null);
        logRequestFailure('Session check', response, body);
        showLoggedOut();
    }
}

loginForm.addEventListener('submit', async (event) => {
    // Forms submit themselves and reload the page by default, we want to handle this one
    // with fetch() instead, so the first order of business is always stopping that.
    event.preventDefault();
    loginError.hidden = true;

    const formData = new FormData(loginForm);
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
        body: JSON.stringify({
            username: formData.get('username'),
            password: formData.get('password'),
        }),
    });

    if (response.ok) {
        // A successful login made the server set the ACCESS_TOKEN cookie for us, we don't
        // touch it ourselves, we just ask refreshSession to notice it's there now.
        loginForm.reset();
        await refreshSession();
    } else {
        const body = await response.json().catch(() => ({}));
        logRequestFailure('Login', response, body);
        loginError.textContent = body.error || 'Login failed';
        loginError.hidden = false;
    }
});

logoutButton.addEventListener('click', async () => {
    // This is itself a state-changing request (it clears your cookie), so it needs the
    // CSRF header too, exactly like the login call above.
    const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfHeaders(),
    });

    if (!response.ok) {
        const body = await response.json().catch(() => null);
        logRequestFailure('Logout', response, body);
    }

    await refreshSession();
});

// --- File upload and listing ------------------------------------------------------

async function loadFiles() {
    const response = await fetch('/api/files', { credentials: 'same-origin' });

    if (!response.ok) {
        const body = await response.json().catch(() => null);
        logRequestFailure('Loading file list', response, body);
        return;
    }

    const files = await response.json();

    fileList.innerHTML = '';

    for (const file of files) {
        const item = document.createElement('li');
        const link = document.createElement('a');
        link.href = `/api/files/${encodeURIComponent(file.storedName)}`;
        link.textContent = `${file.originalName} (${file.sizeBytes} bytes)`;
        item.appendChild(link);
        fileList.appendChild(item);
    }
}

uploadForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    uploadError.hidden = true;

    // FormData, not JSON, here: an <input type="file"> only hands over its bytes once it's
    // wrapped in a FormData, which fetch() then sends as multipart/form-data, exactly what
    // Spring's MultipartFile parameter on the server expects.
    const formData = new FormData(uploadForm);
    const response = await fetch('/api/files', {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfHeaders(),
        body: formData,
    });

    if (response.ok) {
        uploadForm.reset();
        await loadFiles();
    } else {
        const body = await response.json().catch(() => ({}));
        logRequestFailure('Upload', response, body);
        uploadError.textContent = body.error || 'Upload failed';
        uploadError.hidden = false;
    }
});

// --- Startup -----------------------------------------------------------------------

// Runs once, as soon as this script loads. We need the CSRF cookie in place before the
// visitor can even attempt to log in, and we need to know right away whether an existing
// ACCESS_TOKEN cookie from an earlier visit is still valid.
(async function init() {
    await ensureCsrfCookie();
    await refreshSession();
})();
