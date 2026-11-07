import type { BriefingLab, RoomExperience } from "./types";

// "Operation Bare Metal" for the "esxi-virtualization-security" room.
// Script: docs/campaign/53-esxi-virtualization-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Skerry Line (fictional), not the graded tasks' MedCore Health records.
// Signature mechanic: portal in a new vSphere-style skin, walking one alarm back to its grant.
// Game mix: deduce + pathway + portal + rush + spotdiff + tune.
// Lab data differs from the graded tasks: no svc-backup, esx-prod-07, vcsa-04, 10.60.9.14,
// j.marchetti or CHG-77410; the grant here is on a cluster, not the root folder; no moref
// (f1); no change-ticket verdict (ac1); no VPN or guest-agent-offline ranking (q4).

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const tabs = (o: string, hasSvc = false) => [
  { id: o, label: "Summary" },
  { id: `${o}-tasks`, label: "Monitor" },
  ...(hasSvc ? [{ id: `${o}-svc`, label: "Configure" }] : []),
  { id: `${o}-perm`, label: "Permissions" },
];
const sub = (o: string) => [{ id: `${o}-tasks`, label: "Tasks" }, { id: `${o}-events`, label: "Events" }];

const EVENT_COLS = ["Description", "Type", "Date Time", "Target", "User"];
const TASK_COLS = ["Task Name", "Target", "Status", "Initiator", "Start Time", "Completion Time"];
const PERM_COLS = ["User/Group", "Role", "Defined In"];

// ─── The alarm walked back to the session that made it possible ─────────────
const ALARM_LAB: Portal = {
  kind: "portal",
  skin: "vsphere",
  title: "Walk the Alarm Back",
  prompt: "03:12, Saturday. The last ferry is in, and an alarm has just lit on one host. No EDR in the building can tell you a thing about it, so Callum Okafor hands you the vSphere Client: start at the alarm and walk it back, record by record, to the session that made it possible.",
  product: "Virtualization client",
  resource: "vcsa-sk",
  tenant: "skerry.local",
  home: "vc",
  menu: [{
    items: [
      { id: "vc", label: "vcsa-sk" },
      { id: "dc", label: "Skerry", depth: 1 },
      { id: "cl", label: "FERRY-B", depth: 2 },
      { id: "h2", label: "sk-esx-02", depth: 3 },
      { id: "h3", label: "sk-esx-03", depth: 3 },
      { id: "vm", label: "booking-db", depth: 3 },
    ],
  }],
  pages: {
    vc: { heading: "vCenter Details", object: "vcsa-sk", node: "vc", tab: "Summary", tabs: tabs("vc"), tiles: [{ label: "Hosts", value: "6" }, { label: "Virtual Machines", value: "148" }, { label: "Triggered Alarms", value: "1" }] },
    "vc-tasks": { heading: "Tasks", object: "vcsa-sk", node: "vc", tab: "Monitor", tabs: tabs("vc"), sub: sub("vc"), table: { columns: TASK_COLS, rows: [{ id: "vt1", cells: ["Create scheduled snapshot", "booking-db", "Completed", "SKERRY.LOCAL\\svc-veeam", "01:00:04", "01:00:21"] }] } },
    "vc-events": {
      heading: "Events", object: "vcsa-sk", node: "vc", tab: "Monitor", tabs: tabs("vc"), sub: sub("vc"),
      table: {
        columns: EVENT_COLS,
        rows: [
          { id: "ve-svc", cells: ["User SKERRY.LOCAL\\svc-veeam@10.71.2.40 logged in", "Information", "01:00:02", "vcsa-sk", "SKERRY.LOCAL\\svc-veeam"], record: "ve-svc" },
          { id: "ve-bad", cells: ["Cannot login SKERRY.LOCAL\\e.dunn@10.71.6.18", "Warning", "02:44:30", "vcsa-sk", "SKERRY.LOCAL\\e.dunn"], record: "ve-bad" },
          { id: "ve-login", cells: ["User SKERRY.LOCAL\\e.dunn@10.71.6.18 logged in", "Information", "02:46:11", "vcsa-sk", "SKERRY.LOCAL\\e.dunn"], record: "ve-login" },
        ],
      },
    },
    "vc-perm": { heading: "Permissions", object: "vcsa-sk", node: "vc", tab: "Permissions", tabs: tabs("vc"), table: { columns: PERM_COLS, rows: [{ id: "vp1", cells: ["SKERRY.LOCAL\\vsphere-admins", "Administrator", "This object and its children"] }] } },

    dc: { heading: "Datacenter Details", object: "Skerry", node: "dc", tab: "Summary", tabs: tabs("dc"), tiles: [{ label: "Clusters", value: "2" }, { label: "Datastores", value: "3" }] },
    "dc-tasks": { heading: "Tasks", object: "Skerry", node: "dc", tab: "Monitor", tabs: tabs("dc"), sub: sub("dc"), table: { columns: TASK_COLS, rows: [] } },
    "dc-events": { heading: "Events", object: "Skerry", node: "dc", tab: "Monitor", tabs: tabs("dc"), sub: sub("dc"), table: { columns: EVENT_COLS, rows: [] } },
    "dc-perm": { heading: "Permissions", object: "Skerry", node: "dc", tab: "Permissions", tabs: tabs("dc"), table: { columns: PERM_COLS, rows: [{ id: "dp1", cells: ["SKERRY.LOCAL\\vsphere-admins", "Administrator", "vcsa-sk"] }] } },

    cl: { heading: "Cluster Details", object: "FERRY-B", node: "cl", tab: "Summary", tabs: tabs("cl"), tiles: [{ label: "Hosts", value: "3" }, { label: "Virtual Machines", value: "62" }, { label: "Shared datastore", value: "sk-ds-02" }] },
    "cl-tasks": { heading: "Tasks", object: "FERRY-B", node: "cl", tab: "Monitor", tabs: tabs("cl"), sub: sub("cl"), table: { columns: TASK_COLS, rows: [{ id: "ct1", cells: ["Add Permission", "FERRY-B", "Completed", "SKERRY.LOCAL\\e.dunn", "02:51:37", "02:51:37"] }] } },
    "cl-events": {
      heading: "Events", object: "FERRY-B", node: "cl", tab: "Monitor", tabs: tabs("cl"), sub: sub("cl"),
      table: {
        columns: EVENT_COLS,
        rows: [
          { id: "ce-role", cells: ["New role Port-Ops created", "Information", "2026-08-19 14:02:10", "FERRY-B", "SKERRY.LOCAL\\r.mair"], record: "ce-role" },
          { id: "ce-move", cells: ["Migrated manifests-02 from sk-esx-02 to sk-esx-03", "Information", "02:11:48", "FERRY-B", ""], record: "ce-move" },
          { id: "ce-perm", cells: ["Permission created for SKERRY.LOCAL\\svc-tides on FERRY-B, role Administrator, propagation enabled", "Information", "02:51:37", "FERRY-B", "SKERRY.LOCAL\\e.dunn"], record: "ce-perm" },
        ],
      },
    },
    "cl-perm": { heading: "Permissions", object: "FERRY-B", node: "cl", tab: "Permissions", tabs: tabs("cl"), table: { columns: PERM_COLS, rows: [{ id: "cp1", cells: ["SKERRY.LOCAL\\vsphere-admins", "Administrator", "vcsa-sk"] }, { id: "cp2", cells: ["SKERRY.LOCAL\\svc-tides", "Administrator", "This object and its children"] }] } },

    h2: { heading: "Host Details", object: "sk-esx-02", node: "h2", tab: "Summary", tabs: tabs("h2"), tiles: [{ label: "Hypervisor", value: "ESXi 8.0" }, { label: "Virtual Machines", value: "21" }, { label: "State", value: "Connected" }] },
    "h2-tasks": { heading: "Tasks", object: "sk-esx-02", node: "h2", tab: "Monitor", tabs: tabs("h2"), sub: sub("h2"), table: { columns: TASK_COLS, rows: [] } },
    "h2-events": { heading: "Events", object: "sk-esx-02", node: "h2", tab: "Monitor", tabs: tabs("h2"), sub: sub("h2"), table: { columns: EVENT_COLS, rows: [] } },
    "h2-perm": { heading: "Permissions", object: "sk-esx-02", node: "h2", tab: "Permissions", tabs: tabs("h2"), table: { columns: PERM_COLS, rows: [{ id: "h2p", cells: ["SKERRY.LOCAL\\vsphere-admins", "Administrator", "vcsa-sk"] }] } },

    h3: { heading: "Host Details", object: "sk-esx-03", node: "h3", tab: "Summary", tabs: tabs("h3"), tiles: [{ label: "Hypervisor", value: "ESXi 8.0" }, { label: "Virtual Machines", value: "24" }, { label: "State", value: "Connected" }], note: "Triggered alarm: ESXi Host SSH service. The service is off by default on this fleet." },
    "h3-tasks": {
      heading: "Tasks", object: "sk-esx-03", node: "h3", tab: "Monitor", tabs: tabs("h3"), sub: sub("h3"),
      table: {
        columns: TASK_COLS,
        rows: [
          { id: "t-rel", cells: ["Migrate virtual machine", "manifests-02", "Completed", "com.vmware.vsphere.drs", "02:11:02", "02:11:48"], record: "t-rel" },
          { id: "t-ssh", cells: ["Start Service", "sk-esx-03", "Completed", "SKERRY.LOCAL\\svc-tides", "03:09:44", "03:09:45"], record: "t-ssh" },
          { id: "t-rule", cells: ["Refresh Firewall", "sk-esx-03", "Completed", "SKERRY.LOCAL\\svc-tides", "03:09:45", "03:09:45"], record: "t-rule" },
        ],
      },
    },
    "h3-events": {
      heading: "Events", object: "sk-esx-03", node: "h3", tab: "Monitor", tabs: tabs("h3"), sub: sub("h3"),
      table: {
        columns: EVENT_COLS,
        rows: [
          { id: "e-vpx", cells: ["User vpxuser@127.0.0.1 logged in", "Information", "03:09:42", "sk-esx-03", "vpxuser"], record: "e-vpx" },
          { id: "e-ssh", cells: ["SSH for the host sk-esx-03 has been enabled", "Warning", "03:09:45", "sk-esx-03", ""], record: "e-ssh" },
          { id: "e-tools", cells: ["Alarm ESXi Host SSH service on sk-esx-03 changed from Green to Red", "Warning", "03:12:02", "sk-esx-03", ""], record: "e-alarm" },
        ],
      },
    },
    "h3-perm": {
      heading: "Permissions", object: "sk-esx-03", node: "h3", tab: "Permissions", tabs: tabs("h3"),
      table: {
        columns: PERM_COLS,
        rows: [
          { id: "p-admins", cells: ["SKERRY.LOCAL\\vsphere-admins", "Administrator", "vcsa-sk"], record: "p-admins" },
          { id: "p-veeam", cells: ["SKERRY.LOCAL\\svc-veeam", "Backup-Ops", "Skerry"], record: "p-veeam" },
          { id: "p-tides", cells: ["SKERRY.LOCAL\\svc-tides", "Administrator", "FERRY-B"], record: "p-tides" },
        ],
      },
    },

    vm: { heading: "Virtual Machine Details", object: "booking-db", node: "vm", tab: "Summary", tabs: tabs("vm"), tiles: [{ label: "Power Status", value: "Powered On" }, { label: "Guest OS", value: "Windows Server" }, { label: "Host", value: "sk-esx-03" }, { label: "EDR sensor", value: "Online, no detections" }] },
    "vm-tasks": { heading: "Tasks", object: "booking-db", node: "vm", tab: "Monitor", tabs: tabs("vm"), sub: sub("vm"), table: { columns: TASK_COLS, rows: [] } },
    "vm-events": { heading: "Events", object: "booking-db", node: "vm", tab: "Monitor", tabs: tabs("vm"), sub: sub("vm"), table: { columns: EVENT_COLS, rows: [] } },
    "vm-perm": { heading: "Permissions", object: "booking-db", node: "vm", tab: "Permissions", tabs: tabs("vm"), table: { columns: PERM_COLS, rows: [{ id: "vmp", cells: ["SKERRY.LOCAL\\vsphere-admins", "Administrator", "vcsa-sk"] }] } },
  },
  records: {
    "e-ssh": { id: "e-ssh", title: "Event details", facts: [["Event Type ID", "esx.audit.ssh.enabled"], ["Source on the host", "/var/log/vobd.log"], ["User", "(empty)"], ["Target", "sk-esx-03"]] },
    "e-vpx": { id: "e-vpx", title: "Event details", facts: [["Event Type ID", "UserLoginSessionEvent"], ["User", "vpxuser"], ["Note", "vCenter's own agent account on this host"]] },
    "e-alarm": { id: "e-alarm", title: "Event details", facts: [["Event Type ID", "AlarmStatusChangedEvent"], ["User", "(empty)"], ["Note", "This is the alarm you came in on"]] },
    "t-ssh": { id: "t-ssh", title: "Task details", facts: [["Task Name", "Start Service"], ["Service", "TSM-SSH"], ["Target", "sk-esx-03"], ["Initiator", "SKERRY.LOCAL\\svc-tides"], ["Start Time", "03:09:44"]] },
    "t-rel": { id: "t-rel", title: "Task details", facts: [["Task Name", "Migrate virtual machine"], ["Initiator", "com.vmware.vsphere.drs"], ["Note", "The cluster balancing its own load"]] },
    "t-rule": { id: "t-rule", title: "Task details", facts: [["Task Name", "Refresh Firewall"], ["Initiator", "SKERRY.LOCAL\\svc-tides"], ["Note", "Follows the service start, one second later"]] },
    "p-tides": { id: "p-tides", title: "Permission details", facts: [["User/Group", "SKERRY.LOCAL\\svc-tides"], ["Role", "Administrator"], ["Defined In", "FERRY-B"], ["Propagate", "true"]] },
    "p-admins": { id: "p-admins", title: "Permission details", facts: [["User/Group", "SKERRY.LOCAL\\vsphere-admins"], ["Role", "Administrator"], ["Defined In", "vcsa-sk"]] },
    "p-veeam": { id: "p-veeam", title: "Permission details", facts: [["User/Group", "SKERRY.LOCAL\\svc-veeam"], ["Role", "Backup-Ops"], ["Defined In", "Skerry"]] },
    "ce-perm": { id: "ce-perm", title: "Event details", facts: [["Event Type ID", "PermissionAddedEvent"], ["entity", "FERRY-B"], ["principal", "SKERRY.LOCAL\\svc-tides"], ["roleName", "Administrator"], ["propagate", "true"], ["userName", "SKERRY.LOCAL\\e.dunn"], ["createdTime", "02:51:37"]] },
    "ce-role": { id: "ce-role", title: "Event details", facts: [["Event Type ID", "RoleAddedEvent"], ["roleName", "Port-Ops"], ["Note", "August. A role on its own is only a name for a bundle of privileges"]] },
    "ce-move": { id: "ce-move", title: "Event details", facts: [["Event Type ID", "VmMigratedEvent"], ["Note", "Automatic balancing. It changes nobody's rights"]] },
    "ve-login": { id: "ve-login", title: "Event details", facts: [["Event Type ID", "UserLoginSessionEvent"], ["userName", "SKERRY.LOCAL\\e.dunn"], ["ipAddress", "10.71.6.18"], ["createdTime", "02:46:11"], ["fullFormattedMessage", "User SKERRY.LOCAL\\e.dunn@10.71.6.18 logged in as vsphere-client"]], actions: [{ id: "export", label: "Export" }, { id: "wipe", label: "Clear Events" }] },
    "ve-bad": { id: "ve-bad", title: "Event details", facts: [["Event Type ID", "BadUsernameSessionEvent"], ["userName", "SKERRY.LOCAL\\e.dunn"], ["ipAddress", "10.71.6.18"]] },
    "ve-svc": { id: "ve-svc", title: "Event details", facts: [["Event Type ID", "UserLoginSessionEvent"], ["userName", "SKERRY.LOCAL\\svc-veeam"], ["Note", "The nightly backup, on time"]] },
  },
  steps: [
    { id: "host", ask: "The alarm is on sk-esx-03. Open that host in the inventory.", hint: "The tree on the left: vCenter, datacenter, cluster, then its hosts.", target: "menu:h3", why: "Everything in this client hangs off that tree. A host is one physical server, and the red note is the alarm that woke you." },
    { id: "events", ask: "See what the host has recorded. Open its events.", hint: "Monitor tab, then Events under Tasks and Events.", target: "menu:h3-events", why: "Monitor shows the record for the object you have selected, so you are reading this host's story and not the whole fleet's." },
    { id: "ssh", ask: "Open the event that says what actually changed on this host.", hint: "The alarm is only the reaction. Look for the change that caused it.", target: "row:e-ssh", why: "esx.audit.ssh.enabled comes from the host's own vobd.log: proof the change landed on this box. But look at User: it is empty. The host knows what happened, and not who asked." },
    { id: "tasks", ask: "The event names nobody. Go to where vCenter keeps the requests made against this host.", hint: "Tasks sit right beside Events.", target: "menu:h3-tasks", why: "A change pushed through vCenter runs on the host as vCenter's agent, so the person behind it lives in the task record, not in the host's log." },
    { id: "task", ask: "Find the task behind that event: same host, same moment.", hint: "Match it to the time of the SSH event, and read the Task Name.", target: "row:t-ssh", why: "Start Service at 03:09:44, and the record underneath says TSM-SSH. Now you have a name: svc-tides, an account that only reads tide tables." },
    { id: "perm", ask: "svc-tides only reads tide tables. So why was it allowed to do this? Check what this host says it can do.", hint: "Every inventory object has a tab for who can do what on it.", target: "menu:h3-perm", why: "The Permissions tab shows every permission reaching this object, and the Defined In column shows where each one really lives." },
    { id: "who", ask: "Open the permission that explains it.", hint: "Find the account you just named.", target: "row:p-tides", why: "Administrator, and Defined In says FERRY-B. Nobody touched this host directly. The right came down from the cluster above it." },
    { id: "up", ask: "Go to where that permission was defined.", hint: "One level up the tree.", target: "menu:cl", why: "Reading up the tree is how you find the real scope: whatever was granted here reached every host and VM in FERRY-B, not only sk-esx-03." },
    { id: "clev", ask: "Open that object's events and find the moment the right was handed over.", hint: "Monitor, then Events, on the cluster.", target: "menu:cl-events", why: "The grant is a vCenter object, so its record is here on the management plane, never in a host's vobd.log." },
    { id: "grant", ask: "Open the event that made all of it possible.", hint: "Something happened at 02:51. Read the descriptions, not just the times.", target: "row:ce-perm", why: "PermissionAddedEvent, 02:51:37. userName is who gave, principal is who received: e.dunn handed Administrator to svc-tides, propagating, eighteen minutes before SSH came on." },
    { id: "vc", ask: "e.dunn is a booking-desk supervisor. How did that session start? Go to the place vCenter records sign-ins.", hint: "Sign-ins belong to vCenter itself: the top of the tree, then Monitor and Events.", target: "menu:vc-events", why: "Logins are sessions on vCenter, not on any cluster, so you climb to the top object to read them." },
    { id: "login", ask: "Open the session that made the grant.", hint: "It has to be before 02:51, and it has to have worked.", target: "row:ve-login", why: "e.dunn from 10.71.6.18 at 02:46: a booking-desk laptop at a quarter to three, two minutes after a failed try. That is where the next analyst starts." },
    { id: "export", ask: "You have the chain. Keep it for the case.", hint: "The buttons on the event details.", target: "action:export", why: "Exporting preserves the events as they stand, so the chain from sign-in to grant to task to host change survives whatever happens to this vCenter tonight." },
  ],
  traps: {
    "row:e-vpx": "vpxuser is vCenter's own agent account on every managed host. It's how every vCenter change arrives, so naming it attributes nothing.",
    "row:e-tools": "That's the alarm, the reaction to the change. Open the change itself.",
    "row:t-rel": "That's the cluster balancing load an hour earlier. The initiator is an automatic service, and it has nothing to do with SSH.",
    "row:t-rule": "Close, and it's the same account, but this is the firewall refresh that follows the change. Find the task that started the service.",
    "row:p-admins": "That group is the virtualization team, defined at the very top. svc-tides isn't in it. Read the row for the account you named.",
    "row:p-veeam": "That's the backup account, and its role can't start a host service. Read the row for the account you named.",
    "row:ce-role": "That's from August, and creating a role grants nobody anything. A role only means something once it's attached to someone at an object.",
    "row:ce-move": "A VM moved between hosts. It changes nobody's rights.",
    "row:ve-bad": "That one failed, so it made nothing. A grant needs a session that worked.",
    "row:ve-svc": "That's the nightly backup at 01:00. It isn't the session that made this grant.",
    "action:wipe": "Never. That destroys the record you just walked. The next analyst needs every line of it.",
  },
  lesson: "Start at the symptom and walk backwards: the host's event proves the change landed, the vCenter task names who asked, the Permissions tab shows where the right came from, the grant's event says who handed it over, and the sign-in says how they got in. Each record answers one question and hands you the next.",
};

export const ESXI_VIRTUALIZATION_SECURITY: RoomExperience = {
  roomId: "esxi-virtualization-security",
  codename: "Operation Bare Metal",
  theme: "baremetal",
  handler: { name: "Callum Okafor", role: "Virtualization Engineer, Skerry Line" },
  briefing: [
    "Skerry Line. Eleven ferries, thirty islands, and one cold room on the quay where booking, manifests and crew rotas all run as virtual machines on six physical servers.",
    "Every laptop and every guest VM at Skerry has an EDR sensor. The six servers underneath them don't, and can't.",
    "Callum Okafor's warning to every new analyst is the same: the layer that holds everything up is the one layer your tools can't see.",
    "Learn the stack, learn what's blind, then read the hypervisor's own records until one alarm takes you all the way back to how the attacker got in.",
  ],
  mission: "Walk the stack, find what your EDR can't see, work out who could really have done it, walk one alarm back through the vSphere Client, catch the loop in a shell log, tune a rule that fires before the damage, then rebuild a graded hypervisor intrusion.",
  estimate: "~65 min",
  look: { primary: "#22d3ee", secondary: "#a78bfa", warn: "#f97316" },
  scene: "baremetal",
  layout: "stage",
  stations: [
    {
      id: "hypervisor",
      label: "The Hypervisor",
      topic: "Hosts, guests, vCenter and the datastore · why no EDR runs here",
      tagline: "What's under the VM?",
      building: "control",
      taskIds: ["esxf-r1", "esxf-r2", "esxf-q1"],
    },
    {
      id: "grant",
      label: "The Grant",
      topic: "Privileges, roles and permissions · reading vCenter events",
      tagline: "Who was able to, and since when?",
      building: "office",
      taskIds: ["esxf-r3", "esxf-r4", "esxf-la1", "esxf-f1"],
    },
    {
      id: "default",
      label: "The Host's Own Log",
      topic: "vobd.log and esx.audit events · matching host records to vCenter",
      tagline: "One alarm, two logs",
      building: "lab",
      taskIds: ["esxf-r5", "esxf-q2", "esxf-la2", "esxf-ac1"],
    },
    {
      id: "loop",
      label: "The Power-Off Loop",
      topic: "shell.log and vim-cmd · why VMs must stop before their disks can be encrypted",
      tagline: "Read what they typed",
      building: "vault",
      taskIds: ["esxf-r6", "esxf-r7", "esxf-q3"],
    },
    {
      id: "before",
      label: "Before the Damage",
      topic: "Ranking signals by earliness and fidelity · rebuilding the chain",
      tagline: "Finish the story",
      building: "ticket",
      taskIds: ["esxf-r8", "esxf-q4", "esxf-m1", "esxf-o1"],
      boss: true,
    },
  ],
  personas: {
    "esxf-q1": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Every sensor green, right up to the end. Tell me why that isn't a failure of the sensors." },
    "esxf-la1": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Two accounts in one event. Don't mix up who gave and who got." },
    "esxf-f1": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Same log. This time you want vCenter's own ID for the object." },
    "esxf-q2": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Don't start from what it did. Start from what let it." },
    "esxf-la2": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Different file, different machine. Why do you need both?" },
    "esxf-ac1": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Same event as the bad night. Is it the same story?" },
    "esxf-q3": { name: "Callum Okafor", role: "Virtualization Engineer", line: "It's a good rule. What's wrong with having only that one?" },
    "esxf-q4": { name: "Callum Okafor", role: "Virtualization Engineer", line: "You get one rule on the top of the queue. Choose." },
    "esxf-m1": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Six artefacts. Say where each one lives." },
    "esxf-o1": { name: "Callum Okafor", role: "Virtualization Engineer", line: "Write it the way it happened." },
  },
  briefings: {
    // ── Reading 1: the stack ──
    "esxf-r1": [
      {
        kind: "pathway",
        title: "Walk the Stack",
        prompt: "On your first morning Callum Okafor points at a laptop on the quay and a server in the cold room. Booking-db's data is somewhere between the two. Walk the admin's click down to the file that really holds its disk, one hop at a time.",
        goal: "Reach booking-db-flat.vmdk",
        nodes: [
          { id: "admin", label: "Admin browser", sub: "Callum's laptop", x: 12, y: 18 },
          { id: "t2", label: "Laptop hypervisor", sub: "Type 2 test VM", x: 12, y: 72 },
          { id: "vc", label: "vCenter", sub: "appliance, one console", x: 38, y: 18 },
          { id: "e1", label: "sk-esx-03", sub: "ESXi host, runs booking-db", x: 64, y: 14 },
          { id: "e2", label: "sk-esx-02", sub: "ESXi host", x: 40, y: 58 },
          { id: "guest", label: "booking-db", sub: "guest VM", x: 88, y: 26 },
          { id: "ds", label: "sk-ds-02", sub: "shared VMFS datastore", x: 66, y: 60 },
          { id: "vmdk", label: "booking-db-flat.vmdk", sub: "the disk, as a file", x: 88, y: 84 },
        ],
        edges: [["admin", "t2"], ["admin", "vc"], ["vc", "e1"], ["vc", "e2"], ["e1", "guest"], ["e1", "ds"], ["e2", "ds"], ["ds", "vmdk"]],
        route: ["admin", "vc", "e1", "ds", "vmdk"],
        notes: {
          admin: "Nobody here signs in to hosts one by one. An admin opens one console.",
          vc: "vCenter Server is the management plane: one console and one sign-in over the whole fleet. It usually runs as a virtual appliance itself.",
          e1: "ESXi is a Type 1 hypervisor: it runs straight on the hardware with no ordinary operating system underneath. Each server running it is a host.",
          ds: "A datastore is storage formatted with VMFS and shared by every host in the cluster, which is why a VM can move between hosts without its disk moving.",
          vmdk: "There it is: a guest's whole disk is one -flat.vmdk file on the datastore. Remember that it's only a file.",
        },
        traps: {
          t2: "That's Type 2: a hypervisor running as an app on an ordinary OS, like a test VM on a laptop. It manages nothing in the cold room.",
          e2: "sk-esx-02 can reach the same datastore, because it's shared. But booking-db runs on sk-esx-03 today, so that's the host with its hands on the disk.",
          guest: "From inside, the guest believes it owns a disk. It only sees virtual hardware. The real file is outside it, on the datastore, and the guest can't reach it.",
        },
        lesson: "vCenter manages hosts, hosts run guests, and every guest's disk is a file on a datastore the hosts share. A guest is a separate OS with its own users and logs, and the host is a different OS that no guest can see.",
      },
    ],
    // ── Reading 2: what EDR can't see ──
    "esxf-r2": [
      {
        kind: "rush",
        title: "Who Sees It?",
        prompt: "Skerry's EDR console is green from end to end, and Callum wants to know what that's worth. For each thing that happens, call it fast: would a sensor inside a guest VM see it, or is it blind?",
        target: 11,
        trueLabel: "Guest sensor sees it",
        falseLabel: "Blind",
        cards: [
          { id: "ps", text: "winword.exe starts powershell.exe inside a Windows guest", answer: true, why: "A process inside the guest's own OS is exactly what the sensor hooks." },
          { id: "svc", text: "A service is switched on at the host from the vCenter console", answer: false, why: "That happens on the hypervisor. No guest OS is involved, so no guest sensor has anything to see." },
          { id: "task", text: "A new scheduled task appears on a guest", answer: true, why: "It's inside the guest, so it looks the same as on a physical server." },
          { id: "vim", text: "Someone lists every VM from a shell on the host", answer: false, why: "That shell runs on ESXi, and the guests can't see their host's processes." },
          { id: "neigh", text: "Another guest on the same host runs a crypto miner", answer: false, why: "Sharing a host gives no view across. A sensor sees only its own guest." },
          { id: "file", text: "A file lands in C:\\Temp inside a guest", answer: true, why: "A guest's own file system is fully in view." },
          { id: "bin", text: "A binary is copied onto the datastore from the host", answer: false, why: "The datastore sits beneath the guests. To a sensor it doesn't exist." },
          { id: "tools", text: "vCenter runs a command inside a guest through VMware Tools", answer: true, why: "The trigger is outside, but the process really starts inside the guest OS, so the sensor sees that process." },
          { id: "net", text: "A Linux guest opens a connection to an unknown server", answer: true, why: "The guest's own network stack is in view." },
          { id: "clone", text: "A VM's disk file is copied to a second folder on the datastore", answer: false, why: "To the guest nothing happened. Its disk was read from below it." },
          { id: "rdp", text: "One guest connects to another over RDP", answer: true, why: "Both ends are guest OSes, so normal lateral-movement telemetry applies." },
          { id: "fw", text: "A host's firewall ruleset is changed", answer: false, why: "That's host configuration, recorded by the host and not by any guest." },
          { id: "quiet", text: "A sensor goes quiet because its VM was stopped", answer: true, why: "You'll see this one, but only as an agent going offline. It tells you the VM stopped, and nothing about why." },
          { id: "perm", text: "An account is granted a new role in vCenter", answer: false, why: "Permissions live in vCenter. No guest is told." },
        ],
        lesson: "A guest sensor sees its own guest and nothing else. Anything done at the host, the datastore or vCenter leaves every sensor green, because no supported EDR runs on ESXi. That layer has to be watched through its own logs.",
      },
    ],
    // ── Reading 3: permission model ──
    "esxf-r3": [
      {
        kind: "sort",
        title: "Smallest to Biggest",
        prompt: "Callum's rule: nobody reads a vCenter event until they can tell these three apart. Sort each one.",
        buckets: [{ id: "priv", label: "Privilege: one narrow ability" }, { id: "role", label: "Role: a named bundle" }, { id: "perm", label: "Permission: role + who + where" }],
        items: [
          { id: "a", text: "Host.Config.Settings", bucket: "priv", why: "One specific ability: change a host's configuration." },
          { id: "b", text: "VirtualMachine.Interact.PowerOn", bucket: "priv", why: "Dotted names are privileges, the smallest unit vSphere has." },
          { id: "c", text: "Administrator (roleId -1)", bucket: "role", why: "A bundle of nearly every privilege. On its own it gives nobody anything." },
          { id: "d", text: "Backup-Ops: browse VMs and take snapshots", bucket: "role", why: "A custom bundle cut down for one job. Still only a bundle until it's attached." },
          { id: "e", text: "svc-veeam has Backup-Ops on Skerry, propagate true", bucket: "perm", why: "Role, principal and entity together, and that's the only thing that grants anything." },
          { id: "f", text: "ops-night has Read-only on FERRY-A, propagate false", bucket: "perm", why: "It's a weak one, but still a permission: who, what, where, and whether it flows down." },
        ],
      },
      {
        kind: "deduce",
        title: "Who Could Have Stopped It?",
        prompt: "booking-db stopped at 04:10, and the event has no user on it. It lives at Skerry > Ferries (folder) > FERRY-B > booking-db. Callum pulls six accounts' permissions. Only one of them could really have done it. Strike out the rest.",
        nameColumn: "Account",
        columns: ["Role", "Defined on", "Propagate"],
        suspects: [
          { id: "a", name: "a.lund", cells: ["Read-only", "Skerry", "true"] },
          { id: "b", name: "svc-veeam", cells: ["Backup-Ops", "FERRY-B", "true"] },
          { id: "c", name: "ops-night", cells: ["VM Power User", "FERRY-A", "true"] },
          { id: "d", name: "m.ross", cells: ["VM Power User", "FERRY-B", "false"] },
          { id: "e", name: "svc-sched", cells: ["VM Power User", "Ferries", "true"] },
          { id: "f", name: "t.ngata", cells: ["VM Power User", "manifests-02", "false"] },
        ],
        clues: [
          "The role must carry VirtualMachine.Interact.PowerOff. VM Power User does. Read-only and Backup-Ops don't.",
          "The permission must sit on booking-db or on something above it in the inventory.",
          "A permission set above the VM only reaches it if propagate is true.",
        ],
        culprit: "e",
        why: "svc-sched: the right role, on a folder above the VM, flowing down. m.ross has the right role in the right cluster, but without propagate it stops at the cluster object itself. ops-night is in the wrong branch, and a role alone means nothing without a path to the object.",
      },
    ],
    // ── Reading 4: reading a vCenter event ──
    "esxf-r4": [
      {
        kind: "inspect",
        title: "One vCenter Event",
        prompt: "This is the record behind booking-db stopping at 04:10, out of vCenter's event feed. Check each field: what does it tell you, and what doesn't it?",
        artifact: "vCenter event feed · vpxd · vcsa-sk",
        items: [
          { id: "type", text: "eventTypeId: VmPoweredOffEvent", tag: "What happened", tone: "info", note: "vCenter's own name for the action. Rules key on this, because the names follow a pattern you can reason from: UserLoginSessionEvent, BadUsernameSessionEvent, and so on." },
          { id: "time", text: "createdTime: 2026-10-24T04:10:27.114Z", tag: "When", tone: "info", note: "vCenter's time, recorded on the appliance. The host's own logs carry their own stamps." },
          { id: "msg", text: "fullFormattedMessage: booking-db on sk-esx-03 in Skerry is powered off", tag: "For people", tone: "trust", note: "Good for a quick read. A detection rule should use the structured fields, not this sentence." },
          { id: "user", text: "userName: \"\"", tag: "Who? Unknown", tone: "warn", note: "Empty doesn't mean nobody. It means this event doesn't attribute the action to an interactive session, so you go looking for a related record that does." },
          { id: "chain", text: "chainId: 884213", tag: "The thread", tone: "warn", note: "Events from one operation share a chainId. Pull the others on it to rebuild the sequence, instead of reading one line alone." },
          { id: "file", text: "log file: /var/log/vmware/vpxd/vpxd.log", tag: "Where", tone: "info", note: "vpxd is the core vCenter daemon, and this file on the appliance is the management plane's own record, much like the Security log on Windows." },
        ],
      },
    ],
    // ── Reading 5: signature, one alarm through both logs ──
    "esxf-r5": [ALARM_LAB],
    // ── Reading 6: shell.log ──
    "esxf-r6": [
      {
        kind: "spotdiff",
        title: "Spot What Isn't Maintenance",
        prompt: "SSH can be legitimate, and shell.log records every command typed. Left: Callum's patch runbook, the way a real session goes. Right: what sk-esx-03's shell.log holds from last night. Tap the lines that change the story. A harmless difference costs you a life.",
        goodTitle: "Patch runbook",
        suspectTitle: "sk-esx-03 /var/log/shell.log",
        good: [
          "[root]: esxcli system version get",
          "[root]: esxcli system maintenanceMode get",
          "[root]: vim-cmd vmsvc/getallvms",
          "[root]: vim-cmd vmsvc/power.shutdown 14",
          "[root]: esxcli software vib list",
          "[root]: ls /vmfs/volumes/sk-ds-02/",
          "[root]: tail -n 40 /var/log/vmkernel.log",
          "[root]: esxcli network firewall get",
          "[root]: exit",
        ],
        suspect: [
          "[root]: esxcli system version get",
          "[root]: esxcli system hostname get",
          "[root]: vim-cmd vmsvc/getallvms",
          "[root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done",
          "[root]: esxcli software vib list",
          "[root]: ls /vmfs/volumes/sk-ds-02/",
          "[root]: /tmp/.u/upd -p /vmfs/volumes/sk-ds-02",
          "[root]: esxcli network firewall set --enabled false",
          "[root]: cat /dev/null > /var/log/shell.log",
        ],
        diffs: [
          { line: 3, why: "A loop fed by getallvms: every VM on the host, hard power-off, one after another. The runbook shuts one down gracefully. This is a program finding them all." },
          { line: 6, why: "A binary running out of a hidden folder in /tmp against the whole datastore. Nothing legitimate runs on a host that way." },
          { line: 7, why: "The runbook only reads the firewall state. This turns the host's firewall off." },
          { line: 8, why: "Emptying the log that records commands. No maintenance step does this, and it's the reason to ship shell.log off the host." },
        ],
        decoys: [
          { line: 1, why: "Reading the host's name is harmless, and an operator checking they're on the right box does this. It changes nothing." },
        ],
        lesson: "getallvms on its own is ordinary. What gives a session away is the shape: discover everything, stop everything, then run something against the datastore. shell.log holds it verbatim, which makes it the best record of what was really done, so it needs to leave the host.",
      },
    ],
    // ── Reading 7: the lock, and the rule ──
    "esxf-r7": [
      {
        kind: "simulate",
        title: "Can It Write?",
        prompt: "Callum puts four situations on the whiteboard. For each one, run the two checks and see whether a process on the host can rewrite that VM's -flat.vmdk.",
        checks: [
          { name: "Host shell", question: "Is the process running on the host, with the datastore in reach?" },
          { name: "Disk free", question: "Is the VM stopped, so that nothing holds its exclusive lock?" },
        ],
        scenarios: [
          { id: "run", label: "manifests-02 is running", detail: "A process on the host tries to open its -flat.vmdk for writing.", results: ["pass", "fail"], why: ["It has a shell on the host.", "A running VM's disk is held under an exclusive lock."], verdict: "Refused. The lock exists to stop two writers corrupting a disk, and it doesn't care who's asking." },
          { id: "tool", label: "A trusted tool, same VM still running", detail: "A legitimate maintenance tool on the host tries to rewrite the same file.", results: ["pass", "fail"], why: ["It's on the host too.", "The lock is the same lock."], verdict: "Refused as well. It's a safety mechanism, not a security control: it treats everyone alike." },
          { id: "off", label: "rota-01 has been powered off", detail: "The same process tries again after the VM stopped.", results: ["pass", "pass"], why: ["Still on the host.", "Stopping the VM released the lock."], verdict: "Allowed. Nothing else stands between this process and the whole disk, and the guest's sensor stopped along with the guest." },
          { id: "guest", label: "Ransomware inside a running guest", detail: "It encrypts the guest's own documents through the guest OS.", results: ["fail", "fail"], why: ["It's inside the guest, with no view of the datastore.", "The VM is running, and this process never touches the file from outside."], verdict: "Different attack, different layer. It damages files inside one guest, and that guest's sensor can see it happen." },
        ],
      },
      {
        kind: "tune",
        title: "Tune the Power-Off Rule",
        prompt: "Stopping VMs comes first, and it shows in vCenter before any disk is touched. Callum wants a rule on it. Set how many VMs stopped in 10 minutes should alert, and whether an open change record clears it. Catch the attacks without waking him for every patch night.",
        eventColumn: "Night",
        dials: [
          { id: "vms", label: "VMs powered off in 10 minutes, at least", short: "VMs off", min: 1, max: 20, step: 1, start: 1, dir: "above" },
          { id: "chg", label: "Open change records, at most", short: "Changes", min: 0, max: 1, step: 1, start: 1, dir: "below" },
        ],
        events: [
          { id: "a1", label: "Whole host stopped at 04:00", bad: true, values: { vms: 18, chg: 0 } },
          { id: "a2", label: "Half a cluster stopped on a Sunday", bad: true, values: { vms: 9, chg: 0 } },
          { id: "a3", label: "Small host, every VM on it stopped", bad: true, values: { vms: 6, chg: 0 } },
          { id: "g1", label: "Monthly patch night, rolling", bad: false, values: { vms: 16, chg: 1 } },
          { id: "g2", label: "Disaster recovery test", bad: false, values: { vms: 11, chg: 1 } },
          { id: "g3", label: "Dev lab's scheduled nightly stop", bad: false, values: { vms: 8, chg: 0 } },
          { id: "g4", label: "Admin rebuilding two test VMs", bad: false, values: { vms: 2, chg: 0 } },
          { id: "g5", label: "Engineer tidying four old VMs", bad: false, values: { vms: 4, chg: 0 } },
        ],
        goal: { catch: 3, maxFalse: 1 },
        lesson: "The count separates a tidy-up from a sweep, and the change record separates a sweep from a planned one. Set the count too low and you get the tidy-up too; ignore the change record and every patch night pages someone. You'll probably keep one false alarm. That's worth it for a rule that fires while the disks are still intact.",
      },
    ],
    // ── Reading 8: earliness and fidelity ──
    "esxf-r8": [
      {
        kind: "sort",
        title: "Where Does It Go?",
        prompt: "A signal can be early, or certain, and the rule you want is both. Callum is writing Skerry's queue. Put each of these where it belongs.",
        buckets: [{ id: "ctx", label: "Context: too common to alert on" }, { id: "alert", label: "Alert: early and trustworthy" }, { id: "conf", label: "Confirm: certain, but too late to stop it" }],
        items: [
          { id: "a", text: "A vCenter sign-in from the admin subnet at 09:00", bucket: "ctx", why: "It happens all day. It's useful once you're tracing a session, and useless as an alert." },
          { id: "b", text: "A failed vCenter sign-in", bucket: "ctx", why: "Typos are constant. It only matters alongside something else." },
          { id: "c", text: "esx.audit.net.firewall.config.changed with no change booked", bucket: "alert", why: "Host configuration rarely changes, it names the host, and it arrives before any damage." },
          { id: "d", text: "esx.audit.account.password.updated for root, with no change booked", bucket: "alert", why: "It's rare, specific and security-relevant, and it comes well ahead of the impact." },
          { id: "e", text: "Mass rename of disk files seen by the storage array", bucket: "conf", why: "Nearly certain, but it means encryption is already running." },
          { id: "f", text: "The booking site is down and the phones are ringing", bucket: "conf", why: "You can't get surer, and you can't get later. It helps you scope, and it prevents nothing." },
        ],
      },
    ],
  },
};
