import { describe, expect, it } from "vitest";
import { levelTone, RESULT_STATUS, UNAVAILABLE, fmtDate } from "../format";
import { qs } from "../../services/api";

describe("format helpers", () => {
  it("formats UTC dates without milliseconds", () => {
    expect(fmtDate("2026-10-25T22:14:35.123Z")).toBe("2026-10-25 22:14:35Z");
    expect(fmtDate(null)).toBe("—");
  });
  it("maps every backend result status, including unavailable data", () => {
    for (const s of ["ok", "no_data", "error", "not_configured", "rate_limited", "unsupported"]) expect(RESULT_STATUS[s]).toBeDefined();
    expect(UNAVAILABLE).toBe("Donnée indisponible");
  });
  it("gives distinct tones to risk levels", () => {
    expect(levelTone("critique")).not.toEqual(levelTone("faible"));
  });
  it("builds query strings skipping empty values", () => {
    expect(qs({ a: "1", b: "", c: undefined, d: 0 })).toBe("?a=1&d=0");
  });
});
