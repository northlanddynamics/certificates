// The parts of the Deployment Script editor that need no page: which line ending it keeps, and how it reads each
// interpreter. A version is identified by the SHA-256 of its exact content, so the editor must hand back the bytes it was
// given; server/test/script-editor-state.test.ts holds it to that.
import { EditorState, type Extension } from "@codemirror/state";
import { StreamLanguage } from "@codemirror/language";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { powerShell } from "@codemirror/legacy-modes/mode/powershell";

/**
 * The only line separator the editor splits on and writes: CRLF for a script whose every line ends so, else LF. By
 * default CodeMirror splits on CRLF, CR and LF alike and joins with LF, which would change a CRLF script's hash; with
 * LF alone, any CR in a script of mixed endings stays in its line, as it was.
 */
export function lineSeparatorFor(content: string): "\r\n" | "\n" {
  const crlf = content.match(/\r\n/g)?.length ?? 0;
  const lf = content.match(/\n/g)?.length ?? 0;
  return crlf > 0 && crlf === lf ? "\r\n" : "\n";
}

const LANGUAGES = { bash: StreamLanguage.define(shell), powershell: StreamLanguage.define(powerShell) };

/** How the editor reads a script for `interpreter`, for its colours. */
export const scriptLanguage = (interpreter: keyof typeof LANGUAGES): Extension => LANGUAGES[interpreter];

/** The text of an editor's state, with its own line separator: `doc.toString()` would join lines with LF whatever it is. */
export const scriptText = (state: EditorState) => state.sliceDoc();

/** The state of an editor holding `content`, which gives `content` back unchanged (by `scriptText`) until it is edited. */
export const scriptState = (content: string, extensions: Extension[] = []) =>
  EditorState.create({ doc: content, extensions: [EditorState.lineSeparator.of(lineSeparatorFor(content)), ...extensions] });
