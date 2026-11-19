// Minimal end-to-end check: spawns the server over stdio and calls tools.
// Usage: node scripts/smoke.js [toolName] [jsonArgs]
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const client = new Client({ name: "smoke", version: "0.0.0" });
await client.connect(new StdioClientTransport({ command: process.execPath, args: [join(root, "src/index.js")], env: process.env }));

const [tool, json] = process.argv.slice(2);
if (!tool) {
  const { tools } = await client.listTools();
  console.log("tools:", tools.map((t) => t.name).join(", "));
  const { prompts } = await client.listPrompts();
  console.log("prompts:", prompts.map((p) => p.name).join(", "));
} else {
  const res = await client.callTool({ name: tool, arguments: JSON.parse(json || "{}") }, undefined, { timeout: 600_000 });
  console.log(res.content.map((c) => c.text).join("\n"));
  if (res.isError) process.exitCode = 1;
}
await client.close();
