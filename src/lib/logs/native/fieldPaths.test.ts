/**
 * Field rows as a SIEM document view shows them (Tal, 2026-11-23: "events[0].parameters[1].messageValue
 * .parameter[0].value" and "request.ipChain[0].geographicalContext.city" do not look real).
 * Rows follow Kibana / OpenSearch Discover: dotted paths without array positions, a multi-valued field
 * as one JSON list, name/value lists as one field per name (fieldPaths.ts).
 */
import { describe, it, expect } from "vitest";
import { documentRows, rawBlockRows, rowValues, unflattenIndexed } from "./fieldPaths";
import { collectAll } from "../realism/collect";
import { nativeRows } from "./NativeLogContext";
import { flattenRaw } from "@/components/operation/shared";

const rows = (r: Record<string, unknown>) => Object.fromEntries(documentRows(r));

describe("document rows", () => {
  it("Google Workspace Gmail: typed parameters and nested message values read by name", () => {
    const r = rows({
      kind: "admin#reports#activity",
      events: [{ type: "delivery_type", name: "delivery", parameters: [
        { name: "event_info", messageValue: { parameter: [{ name: "mail_event_type", intValue: "1" }, { name: "success", boolValue: true }] } },
        { name: "message_info", messageValue: { parameter: [
          { name: "rfc2822_message_id", value: "<a1@mail.gmail.com>" },
          { name: "subject", value: "Q2 Infrastructure Costs - Summary" },
          { name: "source", messageValue: { parameter: [{ name: "address", value: "t.levy@rocketstack.io" }] } },
          { name: "destination", multiMessageValue: [{ parameter: [{ name: "address", value: "a@x.example" }] }, { parameter: [{ name: "address", value: "b@x.example" }] }] },
          { name: "link_domain", multiValue: ["files.example", "cdn.example"] },
        ] } },
      ] }],
    });
    expect(r).toEqual({
      kind: "admin#reports#activity",
      "events.type": "delivery_type",
      "events.name": "delivery",
      "events.parameters.event_info.mail_event_type": "1",
      "events.parameters.event_info.success": "true",
      "events.parameters.message_info.rfc2822_message_id": "<a1@mail.gmail.com>",
      "events.parameters.message_info.subject": "Q2 Infrastructure Costs - Summary",
      "events.parameters.message_info.source.address": "t.levy@rocketstack.io",
      "events.parameters.message_info.destination.address": '["a@x.example", "b@x.example"]',
      "events.parameters.message_info.link_domain": '["files.example", "cdn.example"]',
    });
  });

  it("Okta: an array of objects is one multi-valued field per leaf, no positions", () => {
    const r = rows({ request: { ipChain: [{ ip: "198.51.100.220", geographicalContext: { city: "Tel Aviv" } }] }, target: [{ type: "User" }, { type: "AppInstance" }] });
    expect(r).toEqual({ "request.ipChain.ip": "198.51.100.220", "request.ipChain.geographicalContext.city": "Tel Aviv", "target.type": '["User", "AppInstance"]' });
  });

  it("M365 name/value lists become one field per name (Elastic o365 style)", () => {
    const r = rows({
      Parameters: [{ Name: "Identity", Value: "j.doe" }, { Name: "ForwardingSmtpAddress", Value: "smtp:x@ext.example" }],
      ModifiedProperties: [{ Name: "StrongAuthenticationMethod", NewValue: "[]", OldValue: "[{...}]" }],
      ExtendedProperties: [{ Name: "UserAgent", Value: "Mozilla/5.0" }],
    });
    expect(r).toEqual({
      "Parameters.Identity": "j.doe",
      "Parameters.ForwardingSmtpAddress": "smtp:x@ext.example",
      "ModifiedProperties.StrongAuthenticationMethod.NewValue": "[]",
      "ModifiedProperties.StrongAuthenticationMethod.OldValue": "[{...}]",
      "ExtendedProperties.UserAgent": "Mozilla/5.0",
    });
  });

  it("Entra modifiedProperties read by displayName; a list with other keys stays a list", () => {
    const r = rows({ targetResources: [{ id: "u1", type: "User", modifiedProperties: [{ displayName: "StrongAuthenticationPhoneAppDetail", oldValue: "[]", newValue: "[{}]" }] }] });
    expect(r).toEqual({
      "targetResources.id": "u1",
      "targetResources.type": "User",
      "targetResources.modifiedProperties.StrongAuthenticationPhoneAppDetail.oldValue": "[]",
      "targetResources.modifiedProperties.StrongAuthenticationPhoneAppDetail.newValue": "[{}]",
    });
    // Named items with other facts (containers, interfaces) are not a name/value list.
    expect(rows({ containers: [{ name: "app", image: "nginx:1.27" }] })).toEqual({ "containers.name": "app", "containers.image": "nginx:1.27" });
    // Duplicate names are not a dictionary either.
    expect(rows({ headers: [{ name: "Cookie", value: "a" }, { name: "Cookie", value: "b" }] })).toEqual({ "headers.name": '["Cookie", "Cookie"]', "headers.value": '["a", "b"]' });
  });

  it("nulls, empty lists and order", () => {
    expect(documentRows({ a: 1, list: [], b: { c: null }, g: [{ t: null }, { t: null }], h: [{ r: [] }, { r: [{ id: "x" }] }] })).toEqual([
      ["a", "1"], ["list", "[]"], ["b.c", "null"], ["g.t", "null"], ["h.r.id", "x"],
    ]);
  });

  it("authored flat keys with positions read like a native document", () => {
    expect(unflattenIndexed({ x: 1 })).toEqual({ x: 1 });
    expect(rawBlockRows({ "data.office365.Operation": "Set-Mailbox", "data.office365.Parameters[0].Name": "Identity", "data.office365.Parameters[0].Value": "j.doe", "rule.groups[0]": "office365", "rule.groups[1]": "mailbox" })).toEqual([
      ["data.office365.Operation", "Set-Mailbox"],
      ["data.office365.Parameters.Identity", "j.doe"],
      ["rule.groups", '["office365", "mailbox"]'],
    ]);
  });

  it("row values of a multi-valued field", () => {
    expect(rowValues('["a", "b"]')).toEqual(["a", "b"]);
    expect(rowValues("[OKTA_SIGN_ON]")).toEqual(["[OKTA_SIGN_ON]"]);
    expect(rowValues("plain")).toEqual(["plain"]);
  });
});

describe("every surface", () => {
  it("no field row a learner sees carries an array position", () => {
    const bad: string[] = [];
    for (const row of collectAll().rows) {
      const keys = row.native
        ? nativeRows(row.native.record as Record<string, unknown>).map(r => r[0])
        : row.raw && typeof row.raw === "object" ? flattenRaw(row.raw as Record<string, unknown>).map(r => r.key) : [];
      const k = keys.find(x => /\[\d+\]/.test(x));
      if (k) bad.push(`${row.surface}:${row.rowId} ${k}`);
    }
    expect(bad.slice(0, 20)).toEqual([]);
  }, 900_000);
});
