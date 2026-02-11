import classNames from "classnames";
import { Verdict } from "../types";

const verdictStyles: Record<Verdict, string> = {
  CONFIRMED: "border-red text-red",
  POSSIBLE: "border-teal text-teal",
  INCOMPLETE: "border-amber text-amber",
  IMPOSSIBLE: "border-border text-muted"
};

export function VerdictPill({ verdict }: { verdict: Verdict }) {
  return (
    <span className={classNames("badge", verdictStyles[verdict])}>
      {verdict}
    </span>
  );
}
