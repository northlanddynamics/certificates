// The upload form reads a Deployment Script's parameter section in the browser, and the guide's examples are offered to
// upload as they are; the web package shares no code with the server, so both are held to the server's here.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { declaredParameters, ScriptParametersError } from "../src/deployment/script-parameters";
import { CERT_VARIABLES, EXAMPLE_SCRIPTS, exampleContent } from "../../web/src/lib/deployment-script-examples";
import { givenValues, MAX_PARAMETERS, readDeclaration } from "../../web/src/lib/script-parameters";

/** What the server makes of `content`: the parameters, or its refusal's message. */
function server(content: string) {
  try {
    return { parameters: declaredParameters(content) };
  } catch (err) {
    if (err instanceof ScriptParametersError) return { problem: err.message };
    throw err;
  }
}

const section = (...lines: string[]) => ["#!/bin/bash", "# deploy-params:begin", ...lines, "# deploy-params:end", "echo ok", ""].join("\n");
const declaring = (json: unknown) => section(...JSON.stringify(json, null, 2).split("\n").map((line) => `# ${line}`));

describe("the web parameter section reader", () => {
  const AGREEING = {
    "no section": "#!/bin/bash\necho ok\n",
    "an empty array": section("# []"),
    "every field": declaring([{ name: "SITE_ID", label: "Site id", description: "The site.", required: true, default: "s-1" }]),
    "a name alone, given its name as label": declaring([{ name: "PORT" }]),
    "a blank label": declaring([{ name: "PORT", label: "  " }]),
    "blank lines and bare #": section("# [", "#", "", '#   { "name": "A" }', "# ]"),
    "CRLF line ends": section("# [", '#   { "name": "A" }', "# ]").replaceAll("\n", "\r\n"),
    "indented markers": "  # deploy-params:begin\n  # []\n  # deploy-params:end\n",
    "two sections": section("# []") + section("# []"),
    "an end with no begin": "# deploy-params:end\n",
    "a begin with no end": "# deploy-params:begin\n# []\n",
    "two ends": section("# []") + "# deploy-params:end\n",
    "a line that is not a comment": section("# [", 'echo "$X"', "# ]"),
    "a bad name": declaring([{ name: "site-id" }]),
    "a name with the prefix": declaring([{ name: "DEPLOY_PARAM_X" }]),
    "a name twice": declaring([{ name: "A" }, { name: "A" }]),
    "too many": declaring(Array.from({ length: MAX_PARAMETERS + 1 }, (_, i) => ({ name: `P${i}` }))),
    "exactly the most": declaring(Array.from({ length: MAX_PARAMETERS }, (_, i) => ({ name: `P${i}` }))),
    "a default with a newline": declaring([{ name: "A", default: "a\nb" }]),
    "a default over 1 KiB": declaring([{ name: "A", default: "é".repeat(513) }]),
  };

  for (const [label, content] of Object.entries(AGREEING)) {
    test(`says what the server says of ${label}`, () => {
      expect(readDeclaration(content)).toEqual(server(content));
    });
  }

  // Their messages are the parser's and the schema library's, which differ between the two; whether each is refused does not.
  const REFUSED = {
    "JSON that does not parse": section("# [", '#   { "name": "A", }', "# ]"),
    "an object, not an array": declaring({ name: "A" }),
    "an entry that is not an object": declaring(["A"]),
    "an unknown field": declaring([{ name: "A", type: "string" }]),
    "no name": declaring([{ label: "A" }]),
    "a name that is not a string": declaring([{ name: 7 }]),
    "required as a string": declaring([{ name: "A", required: "yes" }]),
    "a number default": declaring([{ name: "A", default: 443 }]),
    "a null label": declaring([{ name: "A", label: null }]),
  };

  for (const [label, content] of Object.entries(REFUSED)) {
    test(`refuses ${label}, as the server does`, () => {
      expect(server(content).problem).toBeDefined();
      expect(readDeclaration(content).problem).toBeDefined();
    });
  }

  test("gives the values the server keeps: a blank takes the default, and one still blank is left out", () => {
    const declared = server(declaring([{ name: "A", required: true }, { name: "B", default: "443" }, { name: "C" }, { name: "D", default: "x" }])).parameters!;
    expect(givenValues(declared, { A: "a", B: " ", C: "", D: "y" })).toEqual({ A: "a", B: "443", D: "y" });
  });
});

describe("the guide's example scripts", () => {
  for (const example of EXAMPLE_SCRIPTS) {
    test(`the ${example.title} example's section is one the platform takes, with a required parameter and an optional one`, () => {
      const parameters = declaredParameters(exampleContent(example));
      expect(parameters.some((p) => p.required)).toBe(true);
      expect(parameters.some((p) => !p.required)).toBe(true);
      expect(example.steps.filter((s) => s.yours)).toHaveLength(1);
      // Every parameter it declares, it reads.
      for (const p of parameters) expect(exampleContent(example)).toContain(`DEPLOY_PARAM_${p.name}`);
    });

    test(`docs/deployment-scripts.md shows the ${example.title} example exactly as the app offers it`, () => {
      const docs = readFileSync(new URL("../../docs/deployment-scripts.md", import.meta.url), "utf8");
      expect(docs).toContain("```" + example.interpreter + "\n" + exampleContent(example) + "```");
    });
  }

  test("between them, show a default, a Bash script and a PowerShell one", () => {
    expect(EXAMPLE_SCRIPTS.some((e) => declaredParameters(exampleContent(e)).some((p) => p.default !== undefined))).toBe(true);
    expect(new Set(EXAMPLE_SCRIPTS.map((e) => e.interpreter))).toEqual(new Set(["bash", "powershell"]));
  });

  test("name every variable the Agent sets for a run", () => {
    const agent = readFileSync(new URL("../../agent/internal/deploy/deploy.go", import.meta.url), "utf8");
    const set = [...agent.matchAll(/"(CERT_[A-Z_]+)="/g)].map((m) => m[1]!);
    expect(CERT_VARIABLES.map((v) => v.name).sort()).toEqual(set.sort());
  });
});
