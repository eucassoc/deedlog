// Verification page for deedlog receipts. All checks run in this browser;
// the receipt in the URL fragment is never sent to this page's server.
"use strict";

// ?lang=ja or ?lang=en in the page URL overrides the browser language, so a
// QR code printed for residents opens in their language.
const lang = new URLSearchParams(location.search).get("lang") || navigator.language || "";
const ja = lang.startsWith("ja");
const T = ja ? {
  title: "受領証の確認",
  intro: "この受領証が、運営者の公開した記録に約束どおり含まれているかを、このブラウザの中だけで確かめます。",
  input: "受領証（URL または本文）を貼り付けてください",
  run: "確認する",
  operator: "運営者", index: "記録番号", size: "公開済みの記録数",
  checking: "確認しています…",
  included: ["約束どおり記録されています", "運営者は、この受領証で約束した記録を、連署サーバーが確認した公開記録に含めています。"],
  pending: ["まだ公開記録に含まれていません", "公開記録がこの番号まで届いていません。運営者が宣言した期限を過ぎても変わらない場合は、受領証を保管したうえで問い合わせてください。"],
  broken: ["約束違反が見つかりました", "運営者の公開記録の同じ番号に、別の記録が入っています。下の証明ファイルは、運営者自身の署名だけで誰でも検証できます。"],
  download: "不正の証明をダウンロード（misbehavior.json）",
  error: "確認できませんでした",
  footer: "この確認ページは運営者ではない第三者が提供しています。信頼する運営者と連署サーバーの一覧: registry.json",
} : {
  title: "Receipt check",
  intro: "Checks, entirely in this browser, that the operator kept the promise made in this receipt.",
  input: "Paste the receipt (URL or text)",
  run: "Check",
  operator: "Operator", index: "Record number", size: "Records published",
  checking: "Checking…",
  included: ["Recorded as promised", "The operator's witnessed public record includes the record this receipt promised."],
  pending: ["Not yet in the public record", "The public record does not reach this number yet. If this persists past the operator's declared delay, keep the receipt and contact the operator."],
  broken: ["Broken promise", "The operator's public record holds a different record at this number. The proof below can be checked by anyone with the operator's own keys."],
  download: "Download proof of misbehavior (misbehavior.json)",
  error: "Could not check",
  footer: "This page is run by a party other than the operator. Operators and witnesses it trusts: registry.json",
};

const $ = (id) => document.getElementById(id);

function show(kind, title, detail) {
  const s = $("status");
  s.className = "status " + kind;
  s.hidden = false;
  $("status-title").textContent = title;
  $("status-detail").textContent = detail || "";
}

function call(name, ...args) {
  const r = JSON.parse(window.deedlog[name](...args));
  if (!r.ok) throw new Error(r.error);
  return r;
}

async function fetchText(url) {
  const resp = await fetch(url, { credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" });
  if (!resp.ok) throw new Error(url + ": HTTP " + resp.status);
  return resp.text();
}

async function check(input, registry) {
  $("download").hidden = true;
  show("pending", T.checking);
  try {
    const opened = call("open", registry, input);
    $("details").hidden = false;
    $("operator").textContent = opened.operator + " (" + opened.origin + ")";
    $("index").textContent = String(opened.index);
    $("size").textContent = "";
    const base = opened.url.replace(/\/$/, "");
    const checkpoint = await fetchText(base + "/checkpoint");
    const size = call("checkpointSize", registry, input, checkpoint).size;
    $("size").textContent = String(size);
    const proof = opened.index < size
      ? await fetchText(base + "/proof?index=" + opened.index + "&size=" + size)
      : "";
    const res = call("check", registry, input, checkpoint, proof).result;
    show(res.status, ...T[res.status]);
    if (res.misbehavior) {
      const blob = new Blob([JSON.stringify(res.misbehavior, null, 2) + "\n"], { type: "application/json" });
      const a = $("download");
      a.href = URL.createObjectURL(blob);
      a.textContent = T.download;
      a.hidden = false;
    }
    document.body.dataset.result = res.status;
  } catch (e) {
    show("error", T.error, e.message);
    document.body.dataset.result = "error";
  }
}

async function main() {
  document.documentElement.lang = ja ? "ja" : "en";
  document.title = T.title;
  $("title").textContent = T.title;
  $("intro").textContent = T.intro;
  $("label-input").textContent = T.input;
  $("run").textContent = T.run;
  $("label-operator").textContent = T.operator;
  $("label-index").textContent = T.index;
  $("label-size").textContent = T.size;
  $("footer").textContent = T.footer;

  const ready = new Promise((resolve) => { window.deedlogReady = resolve; });
  const go = new Go();
  const wasm = await WebAssembly.instantiateStreaming(fetch("deedlog.wasm"), go.importObject);
  go.run(wasm.instance);
  await ready;
  const registry = await fetchText("registry.json");

  $("run").addEventListener("click", () => {
    const input = $("input").value.replace(/\r\n/g, "\n").trim();
    if (input) check(input, registry);
  });
  if (location.hash.includes("r=")) {
    $("input").value = location.href;
    await check(location.href, registry);
  }
}

main().catch((e) => show("error", T.error, e.message));
