// A Deployment Script version is identified by the SHA-256 of its exact content, and the Agent runs only a script whose
// content hashes to it. The web editor must therefore give back the bytes it was given, whatever their line endings;
// these tests hold its state (which needs no page) to that.
import { describe, expect, test } from "bun:test";
import { lineSeparatorFor, scriptState, scriptText } from "../../web/src/lib/script-editor-state";
import { EXAMPLE_SCRIPTS, exampleContent } from "../../web/src/lib/deployment-script-examples";

const SCRIPTS = {
  "LF line ends": "#!/bin/bash\necho one\necho two\n",
  "CRLF line ends": "# PowerShell\r\nWrite-Output 'one'\r\nWrite-Output 'two'\r\n",
  "mixed line ends": "echo one\r\necho two\necho three\r\n",
  "a lone CR": "echo one\recho two\n",
  "no line end at all": "echo one",
  "no trailing line end": "echo one\r\necho two",
  "the Bash example": exampleContent(EXAMPLE_SCRIPTS.bash),
  "the PowerShell example, with CRLF": exampleContent(EXAMPLE_SCRIPTS.powershell).replaceAll("\n", "\r\n"),
};

describe("the script editor", () => {
  for (const [label, content] of Object.entries(SCRIPTS)) {
    test(`gives back ${label} unchanged`, () => {
      expect(scriptText(scriptState(content))).toBe(content);
    });
  }

  test("writes the line ending a script already uses when a line is added", () => {
    const crlf = scriptState("one\r\ntwo\r\n");
    const added = crlf.update({ changes: { from: 3, insert: crlf.lineBreak + "between" } }).state;
    expect(scriptText(added)).toBe("one\r\nbetween\r\ntwo\r\n");

    const lf = scriptState("one\ntwo\n");
    expect(scriptText(lf.update({ changes: { from: 3, insert: lf.lineBreak + "between" } }).state)).toBe("one\nbetween\ntwo\n");
  });

  test("keeps CRLF only for a script whose every line ends so", () => {
    expect(lineSeparatorFor("a\r\nb\r\n")).toBe("\r\n");
    expect(lineSeparatorFor("a\r\nb\n")).toBe("\n");
    expect(lineSeparatorFor("a\nb\n")).toBe("\n");
    expect(lineSeparatorFor("")).toBe("\n");
  });
});
