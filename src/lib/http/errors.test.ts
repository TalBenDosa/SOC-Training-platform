// QA phase 7, E-07 / E-09: what a failure looks like on the screen and on the wire.
import { describe, it, expect, vi } from "vitest";
import { apiErrorMessage, displayError, authErrorMessage, ApiError, userMessageFor } from "./apiError";
import { dbFail } from "./dbFail";
import { NETWORK_ERROR } from "./safeFetch";

describe("apiErrorMessage", () => {
  it.each([
    [401, { error: "Authentication required." }, /session expired/i],
    [403, { error: "Your college's licence isn't active." }, /licence isn't active/],
    [429, null, /try again in 7 s/],
    [503, { error: "Couldn't save your answer — please try again." }, /Couldn't save your answer/],
    [500, { error: "TypeError: x is undefined" }, /on our side/],      // never a raw exception
  ])("%i → %s", (status, body, re) => expect(apiErrorMessage(status, body, 7)).toMatch(re));
});

describe("displayError / userMessageFor", () => {
  it("fetch rejection → the network line; HTML body → plain retry; our message passes", () => {
    expect(displayError(new TypeError("Failed to fetch"), "x")).toBe(NETWORK_ERROR);
    expect(displayError(new SyntaxError("Unexpected token '<'"), "x")).toMatch(/unexpected response/);
    expect(displayError(new Error("Only org admins can do that."), "x")).toBe("Only org admins can do that.");
    expect(userMessageFor(new ApiError("Slow down", 429))).toBe("Slow down");
    expect(userMessageFor(new Error("no result for question"))).not.toMatch(/no result/);
  });
});

describe("authErrorMessage", () => {
  it.each([
    [{ message: "Invalid login credentials", status: 400 }, /Incorrect email or password/],
    [{ name: "AuthRetryableFetchError", message: "Failed to fetch" }, /check your connection/],
    [{ message: "Request rate limit reached", status: 429 }, /Too many attempts/],
    [{ message: "Auth session missing!" }, /expired/],
    [{ message: "some internal GoTrue thing" }, /Something went wrong/],
  ])("%j", (err, re) => expect(authErrorMessage(err)).toMatch(re));
});

describe("dbFail", () => {
  it("logs the detail, returns a plain message and the status the client caused", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const uuid = dbFail({ code: "22P02", message: 'invalid input syntax for type uuid: "abc"' }, "api/x");
    expect(uuid.status).toBe(404);
    expect(JSON.stringify(await uuid.json())).not.toMatch(/uuid|syntax/);
    expect((dbFail({ code: "23505", message: 'duplicate key value violates unique constraint "x_pkey"' }, "api/x")).status).toBe(409);
    const generic = dbFail({ message: "relation \"secret_table\" does not exist" }, "api/x");
    expect(generic.status).toBe(500);
    expect(JSON.stringify(await generic.json())).not.toMatch(/secret_table/);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("secret_table"));
    log.mockRestore();
  });
});

describe("fetchOrError (E-10)", () => {
  it("a network failure becomes a 503 with the network message — the caller's !res.ok path handles it", async () => {
    const { fetchOrError, NETWORK_ERROR: NET } = await import("./safeFetch");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    const res = await fetchOrError("/api/org/groups");
    expect(res.status).toBe(503);
    expect((await res.json()).error).toBe(NET);
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    expect((await fetchOrError("/api/org/groups")).status).toBe(200);
    vi.unstubAllGlobals();
  });
});
