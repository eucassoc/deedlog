# Receipt verification page

A static page that checks a deedlog receipt entirely in the browser
(spec/checkpoint.md §7.1 and §9). It is meant to be hosted by a party other
than the operator: a consumer organization, a municipality's privacy office,
or the deedlog project.

## How it works

1. A receipt arrives as a link, `https://<page>/#r=<receipt>`, for example
   from a QR code on a paper receipt. The receipt is in the fragment, which
   browsers never send to the page's server.
2. The page verifies the receipt against the operator's receipt key from
   `registry.json`.
3. It fetches the operator's latest checkpoint (`<url>/checkpoint`) and
   verifies it against the operator's checkpoint key and the witnesses and
   quorum in `registry.json`.
4. If the checkpoint covers the receipt, it fetches the inclusion proof
   (`<url>/proof?index=I&size=N`) and checks it.
5. It shows one of: recorded as promised, not yet in the public record, or
   broken promise, with a downloadable proof of misbehavior that anyone can
   check with `dlog misbehavior check`.

Nothing the operator serves is trusted by itself. An operator that rewrites
history cannot obtain witness cosignatures, so a page that requires them
reports that the published checkpoint is not valid.

`?lang=ja` or `?lang=en` in the page URL sets the language; otherwise the
browser's language is used.

## Hosting

```sh
web/build.sh /path/to/site      # deedlog.wasm, wasm_exec.js, index.html, app.js, style.css
cp registry.json /path/to/site/ # the operators and witnesses you vouch for
```

Serve the directory as static files over HTTPS, with `application/wasm` for
`.wasm`. The page's Content Security Policy allows scripts only from its own
origin and network requests to any origin, because operators' publication
URLs vary.

`registry.example.json` shows the format; its keys are placeholders. Every
operator entry needs the checkpoint key (whose key name is the origin), the
receipt key and the publication URL served by `dlog serve`.

The WebAssembly module is about 4.5 MB (about 1.3 MB compressed).
