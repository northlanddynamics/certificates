import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { Compartment, EditorState } from "@codemirror/state";
import { drawSelection, EditorView, highlightActiveLine, highlightActiveLineGutter, keymap, lineNumbers } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { useEffect, useRef } from "react";
import type { DeploymentScript } from "@/lib/api";
import { scriptLanguage, scriptState, scriptText } from "@/lib/script-editor-state";

// Colours from the app's own tokens, so the editor follows the theme, light or dark.
const highlight = HighlightStyle.define([
  { tag: [tags.comment, tags.lineComment, tags.blockComment], color: "var(--muted-foreground)", fontStyle: "italic" },
  { tag: [tags.keyword, tags.controlKeyword, tags.operatorKeyword], color: "var(--syntax-keyword)", fontWeight: "600" },
  { tag: [tags.string, tags.special(tags.string)], color: "var(--syntax-string)" },
  { tag: [tags.variableName, tags.special(tags.variableName), tags.definition(tags.variableName)], color: "var(--syntax-variable)" },
  { tag: [tags.number, tags.bool, tags.atom], color: "var(--syntax-number)" },
  { tag: [tags.standard(tags.variableName), tags.function(tags.variableName)], color: "var(--syntax-builtin)" },
]);

const theme = EditorView.theme({
  "&": { fontSize: "12px", backgroundColor: "transparent", height: "100%" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--font-mono, ui-monospace, monospace)", lineHeight: "1.6" },
  ".cm-gutters": { backgroundColor: "transparent", color: "var(--muted-foreground)", border: "none" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "color-mix(in oklab, var(--muted) 60%, transparent)" },
  ".cm-cursor": { borderLeftColor: "var(--foreground)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": { backgroundColor: "color-mix(in oklab, var(--primary) 20%, transparent)" },
});

/**
 * A Deployment Script's content, coloured for its interpreter. It gives back exactly the text it was given, line endings
 * included, until it is edited (`scriptState`, read by `scriptText`), since the version is identified by the hash of those bytes. Tab indents;
 * Escape and then Tab moves on, as CodeMirror lets a keyboard leave it.
 */
export default function ScriptEditor({
  value,
  onChange,
  interpreter,
  labelledBy,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  interpreter: DeploymentScript["interpreter"];
  /** The id of the label that names it. */
  labelledBy: string;
  className?: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const language = useRef(new Compartment());
  const changed = useRef(onChange);
  changed.current = onChange;

  // Made once; a new value from outside (an example chosen, the latest version loaded) replaces the document below.
  useEffect(() => {
    view.current = new EditorView({
      parent: host.current!,
      state: stateFor(value, interpreter, language.current, labelledBy, (text) => changed.current(text)),
    });
    return () => view.current?.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const current = view.current;
    if (current && scriptText(current.state) !== value) {
      // A new document can have other line endings, which a state fixes when it is made: start a fresh one.
      current.setState(stateFor(value, interpreter, language.current, labelledBy, (text) => changed.current(text)));
    }
  }, [value, interpreter, labelledBy]);

  useEffect(() => {
    view.current?.dispatch({ effects: language.current.reconfigure(scriptLanguage(interpreter)) });
  }, [interpreter]);

  return <div ref={host} className={className} />;
}

function stateFor(value: string, interpreter: DeploymentScript["interpreter"], language: Compartment, labelledBy: string, onChange: (text: string) => void) {
  return scriptState(value, [
    lineNumbers(),
    highlightActiveLineGutter(),
    history(),
    drawSelection(),
    bracketMatching(),
    highlightActiveLine(),
    keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
    language.of(scriptLanguage(interpreter)),
    syntaxHighlighting(highlight),
    theme,
    EditorView.contentAttributes.of({ "aria-labelledby": labelledBy, spellcheck: "false", autocorrect: "off", autocapitalize: "off" }),
    EditorView.updateListener.of((update) => {
      if (update.docChanged) onChange(scriptText(update.state));
    }),
  ]);
}

/** A script shown, not edited: the same colours as the editor, and the text selectable and copyable as it is. */
export function ScriptView({
  code,
  interpreter,
  label,
  lineNumbers: numbered = false,
  className,
}: {
  code: string;
  interpreter: DeploymentScript["interpreter"];
  /** What it is, for those who cannot see it. */
  label: string;
  lineNumbers?: boolean;
  className?: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const view = new EditorView({
      parent: host.current!,
      state: scriptState(code, [
        ...(numbered ? [lineNumbers()] : []),
        scriptLanguage(interpreter),
        syntaxHighlighting(highlight),
        theme,
        EditorState.readOnly.of(true),
        EditorView.editable.of(false),
        EditorView.contentAttributes.of({ "aria-label": label }),
      ]),
    });
    return () => view.destroy();
  }, [code, interpreter, label, numbered]);
  return <div ref={host} className={className} />;
}
