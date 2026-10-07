#!/usr/bin/env node
/* WebRecon JS endpoint extractor (AST-based, vendored acorn — no npm at runtime).
 *
 * Reads JavaScript from stdin, parses it with acorn, and emits one JSON object:
 *   { ok: true, calls: [ {kind, method, url, line, col, confidence}, ... ] }
 * Detects fetch / XMLHttpRequest.open / axios(.get/.post/.request) / WebSocket /
 * GraphQL. URLs built from string concatenation or template literals are
 * normalized to a {param} template (e.g. "/api/users/"+id -> /api/users/{id}).
 * Never executes the input; parse errors degrade to { ok:false }.
 */
const path = require("path");
const acorn = require(path.join(__dirname, "acorn.js"));
const walk = require(path.join(__dirname, "walk.js"));

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
  });
}

// Turn an AST expression that yields a URL into a {param} template string.
function urlTemplate(node) {
  if (!node) return null;
  switch (node.type) {
    case "Literal":
      return typeof node.value === "string" ? node.value : null;
    case "TemplateLiteral": {
      let out = "";
      for (let i = 0; i < node.quasis.length; i++) {
        out += node.quasis[i].value.cooked || "";
        if (i < node.expressions.length) out += "{" + exprName(node.expressions[i]) + "}";
      }
      return out;
    }
    case "BinaryExpression": {
      if (node.operator !== "+") return null;
      const l = urlTemplate(node.left);
      const r = urlTemplate(node.right);
      const lp = l !== null ? l : "{" + exprName(node.left) + "}";
      const rp = r !== null ? r : "{" + exprName(node.right) + "}";
      // only meaningful if at least one side is a real string
      if (l === null && r === null) return null;
      return lp + rp;
    }
    default:
      return null;
  }
}

function exprName(node) {
  if (!node) return "param";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && node.property && node.property.name) return node.property.name;
  return "param";
}

function normalize(url) {
  if (!url) return url;
  // ${x} leftovers -> {x}; collapse any placeholder content to a bare name token
  return url.replace(/\$\{([^}]*)\}/g, "{$1}").replace(/\{[^}]*\}/g, (m) => {
    const inner = m.slice(1, -1).trim();
    const name = inner.match(/[A-Za-z_$][\w$]*/);
    return "{" + (name ? name[0] : "param") + "}";
  });
}

function conf(url) {
  if (!url) return 0.6;
  return url.includes("{") ? 0.8 : 0.9;
}

function push(calls, kind, method, node, urlNode) {
  const raw = urlTemplate(urlNode);
  if (!raw || (!raw.startsWith("/") && !/^https?:|^wss?:|^ws:/i.test(raw) && !raw.includes("api")))
    return;
  const url = normalize(raw);
  const loc = node.loc ? node.loc.start : { line: 0, column: 0 };
  calls.push({ kind, method, url, line: loc.line, col: loc.column, confidence: conf(url) });
}

function objMethod(objNode) {
  if (!objNode || objNode.type !== "ObjectExpression") return null;
  for (const p of objNode.properties) {
    const key = p.key && (p.key.name || p.key.value);
    if (key === "method" && p.value && p.value.type === "Literal") return String(p.value.value).toUpperCase();
  }
  return null;
}
function objProp(objNode, propName) {
  if (!objNode || objNode.type !== "ObjectExpression") return null;
  for (const p of objNode.properties) {
    const key = p.key && (p.key.name || p.key.value);
    if (key === propName) return p.value;
  }
  return null;
}

async function main() {
  const src = await readStdin();
  let ast;
  try {
    ast = acorn.parse(src, { ecmaVersion: "latest", sourceType: "module", locations: true });
  } catch (e1) {
    try {
      ast = acorn.parse(src, { ecmaVersion: "latest", sourceType: "script", locations: true });
    } catch (e2) {
      process.stdout.write(JSON.stringify({ ok: false, error: String(e2) }));
      return;
    }
  }
  const calls = [];
  walk.simple(ast, {
    NewExpression(node) {
      const c = node.callee;
      if (c && c.name === "WebSocket") push(calls, "websocket", null, node, node.arguments[0]);
    },
    CallExpression(node) {
      const c = node.callee;
      const args = node.arguments || [];
      // fetch(url, {method})
      if (c && c.type === "Identifier" && c.name === "fetch") {
        push(calls, "fetch", objMethod(args[1]) || "GET", node, args[0]);
        return;
      }
      if (c && c.type === "MemberExpression") {
        const prop = c.property && (c.property.name || c.property.value);
        const objName = c.object && (c.object.name || (c.object.property && c.object.property.name));
        // axios.get/post/put/delete/patch(url)
        if (["get", "post", "put", "delete", "patch", "head", "options"].includes(prop) &&
            /axios|http|client|api|\$http/i.test(String(objName || ""))) {
          push(calls, "axios", prop.toUpperCase(), node, args[0]);
          return;
        }
        // axios.request({url, method}) / api.request({...})
        if (prop === "request") {
          const cfg = args[0];
          const u = objProp(cfg, "url");
          if (u) push(calls, "axios", objMethod(cfg) || "GET", node, u);
          return;
        }
        // xhr.open(method, url)
        if (prop === "open" && args.length >= 2) {
          const m = urlTemplate(args[0]);
          push(calls, "xhr", m ? m.toUpperCase() : null, node, args[1]);
          return;
        }
      }
      // axios({url, method}) bare call
      if (c && c.type === "Identifier" && /axios|request/i.test(c.name)) {
        const cfg = args[0];
        const u = objProp(cfg, "url");
        if (u) push(calls, "axios", objMethod(cfg) || "GET", node, u);
      }
    },
  });
  // GraphQL heuristic: any url containing /graphql becomes kind=graphql
  for (const call of calls) if (/\/graphql|\/gql/i.test(call.url)) call.kind = "graphql";
  process.stdout.write(JSON.stringify({ ok: true, calls }));
}
main();
