// Turns accepted LTL properties into the trusted C call filter linked into the harness.
// Each formula becomes a deterministic Spot monitor; every reported call/result event is
// one step. A call is executed only if every monitor has a transition for it; an observed
// result that a monitor rejects aborts as an LTL violation.
// ltl.json: { properties: [{ id, rule, formula, predicates: { name: { meaning, events } }, apis, examples }] }
type Properties = { properties: any[] };

// Printable ASCII API names without quotes or backslashes embed safely in generated C.
export const EVENT = /^(call|ok|fail):([!#-\[\]-~]+)$/;
const OTHER = "<other>";

export interface Monitor {
  id: string;
  start: number;
  // next[state][eventIndex] = next state, or -1 when the event violates the property.
  next: number[][];
}

type Expr = (bits: boolean[]) => boolean;

function parseLabel(label: string): Expr {
  const tokens = label.match(/\d+|[!&|()tf]/g) ?? [];
  let index = 0;
  const peek = () => tokens[index];
  const take = (expected?: string) => {
    const token = tokens[index++];
    if (token === undefined || (expected && token !== expected)) throw new Error(`Bad HOA label: ${label}`);
    return token;
  };
  const primary = (): Expr => {
    const token = take();
    if (token === "!") { const inner = primary(); return bits => !inner(bits); }
    if (token === "(") { const inner = disjunction(); take(")"); return inner; }
    if (token === "t") return () => true;
    if (token === "f") return () => false;
    if (/^\d+$/.test(token)) { const ap = Number(token); return bits => bits[ap]; }
    throw new Error(`Bad HOA label: ${label}`);
  };
  const conjunction = (): Expr => {
    const parts = [primary()];
    while (peek() === "&") { take(); parts.push(primary()); }
    return bits => parts.every(part => part(bits));
  };
  const disjunction = (): Expr => {
    const parts = [conjunction()];
    while (peek() === "|") { take(); parts.push(conjunction()); }
    return bits => parts.some(part => part(bits));
  };
  const expr = disjunction();
  if (index !== tokens.length) throw new Error(`Bad HOA label: ${label}`);
  return expr;
}

// Parse Spot's `ltl2tgba -D -M -H` output and tabulate it over the event alphabet.
export function monitorFromHoa(id: string, hoa: string, predicates: Record<string, { events: string[] }>, events: string[]): Monitor {
  const body = hoa.split("--BODY--");
  if (body.length !== 2) throw new Error(`Malformed HOA for ${id}`);
  const start = Number(/^Start:\s*(\d+)/m.exec(body[0])?.[1]);
  const states = Number(/^States:\s*(\d+)/m.exec(body[0])?.[1]);
  const apLine = /^AP:\s*\d+(.*)$/m.exec(body[0])?.[1] ?? "";
  const aps = [...apLine.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(match => match[1].replace(/\\(.)/g, "$1"));
  if (!Number.isInteger(start) || !Number.isInteger(states)) throw new Error(`Malformed HOA header for ${id}`);
  for (const ap of aps) if (!predicates[ap]) throw new Error(`Undeclared predicate ${ap} in ${id}`);
  const edges: Array<Array<{ label: Expr; to: number }>> = Array.from({ length: states }, () => []);
  let state = -1;
  for (const line of body[1].split("\n").map(value => value.trim())) {
    const header = /^State:\s*(\d+)/.exec(line);
    if (header) { state = Number(header[1]); continue; }
    const edge = /^\[(.*)\]\s*(\d+)/.exec(line);
    if (edge) {
      if (state < 0) throw new Error(`Malformed HOA body for ${id}`);
      edges[state].push({ label: parseLabel(edge[1]), to: Number(edge[2]) });
    }
  }
  const next = edges.map(stateEdges => events.map(event => {
    const bits = aps.map(ap => predicates[ap].events.includes(event));
    return stateEdges.find(edge => edge.label(bits))?.to ?? -1;
  }));
  return { id, start, next };
}

export function eventAlphabet(properties: Properties): string[] {
  const events = new Set<string>();
  for (const property of properties.properties)
    for (const predicate of Object.values(property.predicates)) for (const event of predicate.events) events.add(event);
  return [...[...events].sort(), OTHER];
}

const eventIndex = (events: string[], event: string) => {
  const index = events.indexOf(event);
  return index >= 0 ? index : events.length - 1;
};

// Mechanically confirm each example against its own monitor: allowed examples must run to
// completion, disallowed ones must be rejected at some event.
export function checkExamples(properties: Properties, monitors: Monitor[], events: string[]): void {
  for (const [i, property] of properties.properties.entries()) {
    for (const example of property.examples) {
      let state = monitors[i].start;
      let rejectedAt = -1;
      for (const [step, event] of example.events.entries()) {
        state = monitors[i].next[state][eventIndex(events, event)];
        if (state < 0) { rejectedAt = step; break; }
      }
      if (example.allowed && rejectedAt >= 0)
        throw new Error(`${property.id}: allowed example ${JSON.stringify(example.events)} is rejected by the formula at event ${rejectedAt}`);
      if (!example.allowed && rejectedAt < 0)
        throw new Error(`${property.id}: disallowed example ${JSON.stringify(example.events)} is accepted by the formula`);
    }
  }
}

const cString = (value: string) => JSON.stringify(value);

export const MONITOR_HEADER = `#ifndef PREQED_LTL_H
#define PREQED_LTL_H
#ifdef __cplusplus
extern "C" {
#endif
/* Trusted PreQED LTL call filter, generated by the Validator from accepted LTL. */
void preqed_reset(void);                      /* call first in every LLVMFuzzerTestOneInput */
int preqed_call(const char *api);             /* 1: perform the call now; 0: skip it */
void preqed_result(const char *api, int ok);  /* report the performed call's outcome */
#ifdef __cplusplus
}
#endif
#endif
`;

export function monitorSource(monitors: Monitor[], events: string[]): string {
  const count = monitors.length;
  const width = events.length;
  const table = monitors.flatMap(monitor => monitor.next.flat());
  const offsets: number[] = [];
  let offset = 0;
  for (const monitor of monitors) { offsets.push(offset); offset += monitor.next.length * width; }
  const named = events.slice(0, -1).map(event => EVENT.exec(event)!);
  const array = (values: (string | number)[]) => `{ ${values.length ? values.join(", ") : "0"} }`;
  return `/* Generated by the PreQED Validator. Do not edit. */
#include "preqed_ltl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREQED_PROPERTIES ${count}
#define PREQED_EVENTS ${width}
static const char *const preqed_kinds[] = ${array(named.map(match => cString(match[1])))};
static const char *const preqed_apis[] = ${array(named.map(match => cString(match[2])))};
static const char *const preqed_ids[] = ${array(monitors.map(monitor => cString(monitor.id)))};
static const int preqed_start[] = ${array(monitors.map(monitor => monitor.start))};
static const int preqed_offset[] = ${array(offsets)};
static const int preqed_next[] = ${array(table)};
static int preqed_state[PREQED_PROPERTIES ? PREQED_PROPERTIES : 1];

void preqed_reset(void) {
  for (int p = 0; p < PREQED_PROPERTIES; p++) preqed_state[p] = preqed_start[p];
}

static int preqed_event(const char *kind, const char *api) {
  for (int e = 0; e < PREQED_EVENTS - 1; e++)
    if (!strcmp(preqed_kinds[e], kind) && !strcmp(preqed_apis[e], api)) return e;
  return PREQED_EVENTS - 1;
}

static int preqed_step(const char *kind, const char *api, int observed) {
  int event = preqed_event(kind, api);
  int next[PREQED_PROPERTIES ? PREQED_PROPERTIES : 1];
  for (int p = 0; p < PREQED_PROPERTIES; p++) {
    next[p] = preqed_next[preqed_offset[p] + preqed_state[p] * PREQED_EVENTS + event];
    if (next[p] >= 0) continue;
    if (!observed) return 0;
    fprintf(stderr, "PREQED LTL VIOLATION: property %s rejects observed event %s:%s\\n", preqed_ids[p], kind, api);
    abort();
  }
  for (int p = 0; p < PREQED_PROPERTIES; p++) preqed_state[p] = next[p];
  return 1;
}

int preqed_call(const char *api) { return preqed_step("call", api, 0); }
void preqed_result(const char *api, int ok) { preqed_step(ok ? "ok" : "fail", api, 1); }
`;
}
