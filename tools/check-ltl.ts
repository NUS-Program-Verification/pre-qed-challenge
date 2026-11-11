import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { monitorFromHoa, eventAlphabet, checkExamples, monitorSource, MONITOR_HEADER } from "./monitor.ts";
const props = JSON.parse(readFileSync(process.argv[2], "utf8"));
const events = eventAlphabet(props);
const monitors = props.properties.map((p: any) => {
  const hoa = execFileSync("ltl2tgba", ["-D", "-M", "-H", "-f", p.formula]).toString();
  return monitorFromHoa(p.id, hoa, p.predicates, events);
});
checkExamples(props, monitors, events);
writeFileSync(process.argv[3] + "/preqed_ltl.c", monitorSource(monitors, events));
writeFileSync(process.argv[3] + "/preqed_ltl.h", MONITOR_HEADER);
console.log("ok: " + monitors.length + " monitors, " + events.length + " events");
