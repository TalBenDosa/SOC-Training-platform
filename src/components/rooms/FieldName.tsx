import React from "react";
import { cn } from "@/lib/utils";

/**
 * The name column of a raw log row. Real field names run long
 * (winlog.event_data.AuthenticationPackageName is 43 characters) and have no spaces,
 * so a fixed-width column let them spill over the value. This column takes a share of
 * the row and wraps: at a dot or underscore first, anywhere if a segment is still too long.
 */
export function FieldName({ name, className }: { name: string; className?: string }) {
  const parts = name.split(/(?<=[._])/);
  return (
    <span className={cn("w-[42%] shrink-0 text-cyber-300 [overflow-wrap:anywhere]", className)}>
      {parts.map((p, i) => <React.Fragment key={i}>{p}{i < parts.length - 1 && <wbr />}</React.Fragment>)}
    </span>
  );
}
