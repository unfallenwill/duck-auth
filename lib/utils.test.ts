/**
 * Unit tests for lib/utils.ts.
 */
import { describe, it, expect } from "vitest";
import { cn } from "@/lib/utils";

describe("cn", () => {
  it("merges plain class names", () => {
    expect(cn("px-2", "py-1")).toBe("px-2 py-1");
  });

  it("deduplicates conflicting tailwind classes", () => {
    // twMerge should resolve px-2 vs px-4 → last wins.
    expect(cn("px-2", "px-4")).toBe("px-4");
  });

  it("handles conditional (falsy) values", () => {
    expect(cn("base", false && "hidden", undefined, null, "visible")).toBe(
      "base visible",
    );
  });

  it("handles empty input", () => {
    expect(cn()).toBe("");
  });
});
