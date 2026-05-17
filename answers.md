# Cybersecurity supervision — answers

> **Placeholder.** Replace this whole file with your real answers when you're ready. The token `{{PASSWORD}}` will be replaced everywhere it appears with whatever the visitor typed into the fake Raven login.

## Q1: Some question

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

## Q2: Some other question

Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.

## Q3: Phishing demonstration

I built a fake Raven login page hosted on GitHub Pages. When the target visits the link and enters their credentials, the password is captured client-side and passed to this page via the URL fragment, then injected into the rendered answer.

The password captured in this demo was: {{PASSWORD}}

Because the password lives in the URL fragment (`#...`), it is **never** sent to GitHub's servers — the browser strips the fragment before making the HTTP request. So there is no log of the captured value anywhere; it exists only in the visitor's address bar.
