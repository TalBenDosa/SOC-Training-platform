import type { RoomExperience } from "./types";

// "Operation Bad News" for the "customer-communication" room.
// Script: docs/campaign/64-customer-communication.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Task order changed so each reading sits with the tasks it teaches:
// cc-read-1, cc-q2 | cc-read-2, cc-q1, cc-q3 | cc-read-3, cc-log-1 | cc-ac1
// (room order was cc-read-1, cc-read-2, cc-read-3, cc-q1, cc-q2, cc-q3, cc-log-1, cc-ac1).
//
// Lanternwatch Managed SOC (fictional MSSP) and its client Pennywhistle Toys (fictional), not the
// graded tasks' Acme Corp and GlobalFinance records.
// Signature mechanic: real `chat` labs where the learner types to a frightened client and must
// say what is known, what is not and what happens next, without promising or speculating.
// Game mix: chat + defuse + rush.
// Lab data differs from the graded tasks: the jargon lines use a web back door and rule scores,
// never T1078 or impossible travel (q2); priority rises because a stolen contractor account
// reaches a second server, never a CEO mailbox after a password reset (q1); the pushback is an
// order server before a sale with a standby server on offer, never a CFO's laptop and a loan
// device (q3); the breach is a stale phone number, 2 minutes late on 21:48 + 15, and the safety
// net is taught on 45 of 60 minutes and 3 of 4 hours, never a pager chain or minute 12 of 15
// (log-1); the clock drill's P1 clause covers customer and payment systems and its cases are a
// skimming script and a stopped remote tool, never ransomware or a workstation (ac1).
//
// How chat grades: a typed message against regexes, case-insensitive, first hit wins. So the
// failure rules come first and fire on every goal, and each
// goal ends in partial rules that have Odalys ask for the missing part, then a catch-all that
// coaches. `said()` keeps a rule from firing on its own negation: "I can't promise the sale
// will open" must pass where "I promise the sale will open" must not. No lookbehind: it breaks
// new RegExp on older Safari. Curly apostrophes from phone keyboards are why every contraction
// is written with `.?`.
// Both chats set memory: true, so winning rules read everything said toward the goal and every
// other rule reads only the last message. Failure rules run first, so a bad message never wins.
// In the `whole` goal the partials ask for the part after the one just given (known, then
// unknown, then next), so a learner answering one part at a time is led round to a win.

/** Words that negate or hedge the rest of their clause. */
const NOT = "\\b(?:can.?t|cannot|can not|won.?t|wouldn.?t|don.?t|do not|doesn.?t|does not|isn.?t|is not|aren.?t|are not|not|no|never|unable|too early|haven.?t|have not|hasn.?t|has not|unsure|whether|if|until)\\b";
/** Matches `phrase` only when nothing earlier in its own clause negates it. */
const said = (phrase: string, also = "") => `(?:^|[.!?;,:]\\s*|\\bbut\\s+|\\band\\s+)(?:(?!${NOT}${also})[^.!?;,:])*(?:${phrase})`;

const JARGON = "web.?shell|\\bt\\d{4}\\b|\\biocs?\\b|\\bc2\\b|command.and.control|lateral|exfil|beacon|persistence|payload|\\bedr\\b|\\bsiem\\b|\\bttps?\\b|threat actor|initial access|\\bdmz\\b";
const SPECULATE = "\\bprobably\\b|\\b(?:un)?likely\\b|\\b(?:i|we) (?:think|guess|bet|suspect|assume|reckon|believe|imagine)\\b|(?:don.?t|do not) (?:think|believe)\\b|\\bmy (?:guess|hunch|feeling)\\b|\\bmust (?:be|have)\\b|\\balmost certainly\\b|\\bseems? (?:like|to)\\b|\\blooks? like\\b|\\bsounds? like\\b|\\bappears? to\\b|\\bmaybe\\b|\\bperhaps\\b";
const HEDGE = "\\b(?:may|might|could) (?:be|have)\\b";
const CULPRIT = "russia|china|chinese|north korea|\\biran|nation.?state|state.?sponsored|organi[sz]ed crime|crime gang|a competitor|\\brival|\\binsider|disgruntled|teenager|script kidd";
const COMFORT = [
  "don.?t worry|do not worry|not to worry|nothing to worry|no need to (?:worry|panic)",
  "under control",
  "\\b(?:everything|it|this|you|we|customers?|data|details|records|information)(?:.s| is| are|.re| will be|.ll be| should be| are going to be| is going to be) (?:all |completely |totally |perfectly |absolutely )?(?:fine|safe|ok|okay|secure|alright|all right|good|protected)\\b|\\ball (?:good|fine|ok|okay)\\b",
  "nothing (?:was|has been|got|were) (?:taken|stolen|lost|accessed|leaked|copied)",
  "no (?:customer |personal )?(?:data|details|records|information) (?:was|were|has been|have been|got) (?:taken|stolen|lost|accessed|leaked|copied)",
  "(?:it|this|the (?:attack|threat|incident|problem|breach))(?:.s| is| has been| was)? (?:all |now )?(?:over|fixed|solved|sorted|finished|resolved|gone|dealt with)",
].join("|");
const SALE = "\\bsale (?:will|can|is going to|should|is|goes)\\b";
const PROMISE = "\\b(?:promise|guarantee|assure you|swear|give you my word)(?![^.!?;,]*(?:update|call|message|ring|back to you|let you know|keep you|tell you|hear from))";
const BLAME = "\\b(?:your|you)(?:.re| are| were)? (?:own )?(?:fault|mistake|to blame)|\\byou should have";
/** A loss nobody has confirmed, stated as fact. "What data was taken" asks; it doesn't claim. */
const OVERCLAIM = "\\b(?:customer|details?|data|records?|information|names|addresses)[^.!?;,]{0,30}\\b(?:were|was|have been|has been|got|are|is)\\s+(?:all\\s+|already\\s+|definitely\\s+)?(?:stolen|taken|copied|gone|lost|leaked)\\b|\\bthey(?:.ve| have| got| took| stole| copied)\\s+(?:got\\s+)?(?:all\\s+)?(?:your|the|our|every)\\b[^.!?;,]{0,20}\\b(?:customer|details|data|records)|\\ball (?:of )?your (?:servers|systems|computers|machines|data)\\b";
const ASKING = "|\\b(?:what|which|how much|how many)\\b";
/** "Every hour we delay" and "while we wait" argue against waiting, they don't agree to it. */
const COSTING = "|\\b(?:while|every (?:hour|minute|second|moment)|each (?:hour|minute)|the (?:longer|more))\\b";

// Station 1 chat: the parts of a first update.
const BAD = "(?:back ?door|intru|broke in|broken in|got in\\b|got into|gained access|hack|attacker|malicious|malware|unauthori[sz]ed|hidden|virus|breach|compromis)";
const CUT = "(?:isolat|contain(?:ed|ing|ment)?\\b(?! nothing)|cut(?:ting)? (?:\\w+ ){0,3}off|disconnect|off (?:the|your) network|offline|quarantin|unplug|t(?:ook|ak(?:e|en|ing)) (?:\\w+ ){0,3}off|(?:switch|turn|shut)(?:ed|ing|ting)? (?:\\w+ ){0,3}(?:off|down)|removed? (?:\\w+ ){0,3}from (?:the|your) network|locked (?:\\w+ ){0,3}down|blocked (?:all )?access|\\bpull)";
const UNKNOWN = "(?:(?:don.?t|do not|not|yet to|unable to|can.?t|cannot|can not|haven.?t|have not|hasn.?t|has not)\\s+(?:\\w+\\s+){0,3}(?:know|known|confirm|confirmed|say|tell|sure|established?|determined?|clear|worked out|found out|finished)|\\bunknown\\b|too early|too soon|unclear|\\bunsure\\b|uncertain|no idea|(?:don.?t|do not) have (?:an? |the )?answer|(?:can.?t|cannot|can not) (?:answer|rule)|won.?t know|yes or (?:a )?no|still (?:working out|finding out|establishing|checking (?:whether|if)|trying to)|(?:trying|working|need) to (?:find out|work out|establish|determine)|no (?:answer|evidence|sign|indication)[^.!?]*\\b(?:yet|so far))";
/** The chair's question is about customers: an unknown has to be about them to answer it. */
const CUSTOMERS = "(?:customer|details|\\bdata\\b|records|information|personal|\\bnames?\\b|\\btaken\\b|\\btook\\b|stolen|copied)";
const UNKNOWN_CUSTOMERS = `(?:${UNKNOWN}[^.!?]*${CUSTOMERS}|${CUSTOMERS}[^.!?]*${UNKNOWN})`;
const WORK = "(?:check|review|go(?:ing)? through|look(?:ing)? (?:at|into|through)|still looking|(?:we.?re|we are|is|are) on it|digging|investigat|examin|analy|trac|work(?:ing)? (?:on|out|through)|find(?:ing)? out)";
const TIME = "(?:\\b(?!21[:.]?06)(?:\\d{1,2}[:.]\\d{2}(?:\\s?[ap]m)?|(?:[01]\\d|2[0-3])[0-5]\\d)\\b|\\b\\d{1,2}\\s?(?:pm|am|o.?clock)\\b|half ?past|half (?:\\d{1,2}|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\\b|half an hour|\\b\\d{1,3}\\s?(?:min|mins|minutes|hours?)\\b|(?:ten|fifteen|twenty|thirty|forty|sixty) minutes|an hour|the hour)";
const UPDATE = "(?:update|call|ring|phone|message|back to you|let you know|hear from|tell you|report|check in|speak)";
const NEXT = `(?:${UPDATE}[^.!?]{0,60}${TIME}|${TIME}[^.!?]{0,60}${UPDATE})`;

// Station 2 chat: the three ways a pushback conversation goes wrong.
const CAVE = `\\b(?:we|i)(?:.ll| will| can| could| are happy to| am happy to)? (?:wait|hold off|leave it|delay|put (?:it|this) off)\\b|\\b(?:ok|okay|fine|agreed?|no problem|alright)\\b(?:(?!${NOT})[^.!?;]){0,30}\\b(?:wait|hold off|leave it|until (?:morning|saturday))\\b`;
const OVERRIDE = "(?:isolat|cut|pull|disconnect|take)[^.!?;]{0,40}\\b(?:anyway|regardless|whether you like|no matter what|either way)\\b|\\bpolicy\\b|no choice";
const HANDOFF = "tier ?(?:3|three)|\\bt3\\b|my (?:manager|boss)|someone (?:else|senior)|not my (?:job|remit)|above my";
const CONFIDENT = "\\byes\\b|\\bsure\\b|certain|confiden|\\breal\\b|confirmed|definitely|absolutely|no doubt";
const SAW = "(?:account|sign(?:ed|ing)?.?in|log(?:ged)?.?(?:in|on)|pw-ord-01|order server|address)";
const NOW = "(?:\\bnow\\b|tonight|straight away|right away|immediately|at once|as soon as possible|\\basap\\b)";
const STANDBY = "(?:standby|pw-ord-02|spare|second server|fail ?over|other server|backup server)";
const THEIR_DATA = "(?:customer|record|address|detail|personal|\\bdata\\b|\\bnames?\\b)";
const THEFT = "(?:cop(?:y|ied|ying)|\\btaken\\b|take (?:your|every|all|the)|steal|stolen|\\bsee\\b|\\bget (?:your|every|all|the|at|hold)|\\bsell\\b|grab|walk away with|\\breach|breach|\\bread\\b|access|leak|\\blose\\b|expos|download)";

export const CUSTOMER_COMMUNICATION: RoomExperience = {
  roomId: "customer-communication",
  codename: "Operation Bad News",
  theme: "badnews",
  handler: { name: "Dmitri Asante", role: "Client Services Lead, Lanternwatch Managed SOC" },
  briefing: [
    "Lanternwatch Managed SOC watches other companies' networks through the night, and tonight one of them is Pennywhistle Toys.",
    "The Black Friday sale opens at midnight, and most of Pennywhistle's year runs through one web store.",
    "At 21:06 Lanternwatch cut an infected web server off the network. The managing director has just read the email.",
    "Dmitri Asante hands you the chat. Say what is known, what isn't and what happens next, and keep to the clock.",
  ],
  mission: "Turn analyst language into client language, separate what you know from what you don't, give a frightened client a true first update, read the SLA clock, hold your ground on containment, own a missed deadline, then make the call on the final case.",
  estimate: "~45 min",
  look: { primary: "#e879f9", secondary: "#bef264", warn: "#f43f5e" },
  scene: "facilitybadnews",
  layout: "facility",
  story: {
    intro: { title: "Midnight Sale", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-intro-b55e6624.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-intro-dac2b08e.jpg" },
    afterStation: {
      firstupdate: { title: "Still Inside", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-ch2-efc8031f.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-ch2-d80ac596.jpg" },
      clock: { title: "The Red Line", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-ch3-5c19d5e5.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-ch3-813f592d.jpg" },
      badnews: { title: "Bad News", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-finale-4b1e2297.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/customer-communication/badnews-finale-03ea472a.jpg" },
    },
  },
  stations: [
    {
      id: "firstupdate",
      label: "The First Update",
      topic: "The SOC-as-a-Service model · translating technical language · what is known and what is not",
      tagline: "What do you tell a frightened client?",
      building: "office",
      taskIds: ["cc-read-1", "cc-q2"],
    },
    {
      id: "clock",
      label: "The Clock",
      topic: "SLA tiers P1 to P4 · choosing the channel · client pushback · the security advisory",
      tagline: "Which clock is running?",
      building: "control",
      taskIds: ["cc-read-2", "cc-q1", "cc-q3"],
    },
    {
      id: "apology",
      label: "The Apology",
      topic: "SLA breaches · apologies and corrective actions · the After-Action Review",
      tagline: "Two minutes late is late",
      building: "archive",
      taskIds: ["cc-read-3", "cc-log-1"],
    },
    {
      id: "badnews",
      label: "Bad News",
      topic: "Weighing a contract clause against a good outcome",
      tagline: "It's stopped. Now what?",
      building: "ticket",
      taskIds: ["cc-ac1"],
      boss: true,
    },
  ],
  personas: {
    "cc-q2": { name: "Dmitri Asante", role: "Client Services Lead", line: "Read this draft the way the client will." },
    "cc-q1": { name: "Dmitri Asante", role: "Client Services Lead", line: "This ticket is twenty minutes old. Look at it again." },
    "cc-q3": { name: "Dmitri Asante", role: "Client Services Lead", line: "The client has said no. What do you say back?" },
    "cc-log-1": { name: "Dmitri Asante", role: "Client Services Lead", line: "The tracker flagged this one. Read all of it." },
    "cc-ac1": { name: "Dmitri Asante", role: "Client Services Lead", line: "18:07 on the clock. Your call." },
  },
  briefings: {
    // ── Reading 1: client language and the first update ──
    "cc-read-1": [
      {
        kind: "rush",
        title: "Send It or Rewrite It?",
        prompt: "An MSSP (Managed Security Service Provider) runs the SOC for other companies, so every line you write lands on someone who doesn't speak SOC. Dmitri reads you lines from draft updates to Pennywhistle's managing director. Would each one work when read at a kitchen table?",
        trueLabel: "Send it",
        falseLabel: "Rewrite it",
        target: 10,
        seconds: 60,
        cards: [
          { id: "c1", text: "T1505.003 observed on PW-WEB-02.", answer: false, why: "A technique number is a filing code for analysts. Say what it means for them: a hidden back door on a web server." },
          { id: "c2", text: "One of your web servers had a hidden back door. We've isolated it.", answer: true, why: "What happened and what's already been done, in words anyone can repeat." },
          { id: "c3", text: "Rule 4471 fired with a risk score of 87.", answer: false, why: "Your rule and your score are your tools. The client needs to know what it means for them, not which alarm rang." },
          { id: "c4", text: "East-west SMB traffic seen from the DMZ host.", answer: false, why: "True, and useless at a kitchen table. In plain words: someone tried to move from one of your servers to another." },
          { id: "c5", text: "We need you to change the contractor's password tonight.", answer: true, why: "A clear action, with a person and a time. This is what a client can actually do." },
          { id: "c6", text: "Nothing to worry about, everything is fine.", answer: false, why: "False reassurance is as harmful as jargon. A client who believes it won't act, and you haven't checked." },
          { id: "c7", text: "The shop is still taking orders on your other web server.", answer: true, why: "Business impact, stated as a fact. It's the first thing an owner wants to know." },
          { id: "c8", text: "Full IOC list below: hashes, domains, user agents.", answer: false, why: "Indicators of Compromise are useful to their IT team as an attachment. They're not the opening line, and a missing list is never the main problem." },
          { id: "c9", text: "Our SIEM raised a high-fidelity correlated detection.", answer: false, why: "It names the tool and says nothing about the client. Which product raised it doesn't help them act." },
          { id: "c10", text: "Someone outside your company got into this server with a stolen account.", answer: true, why: "Plain words for how it happened, with no mechanics to decode." },
          { id: "c11", text: "You've been hacked and all your data is at risk!", answer: false, why: "Panic, and more than you know. It creates fear without telling the client what is true or what to do." },
          { id: "c12", text: "We don't yet know if customer details were taken. We're checking now.", answer: true, why: "An honest gap and the work to close it. Not knowing is fine when you say so." },
          { id: "c13", text: "Attacker dwell time was 41 minutes pre-containment.", answer: false, why: "Dwell time is your word. For them: someone was inside for 41 minutes before we cut them off." },
          { id: "c14", text: "Next update at 22:30, sooner if anything changes.", answer: true, why: "A client who knows when they'll hear from you can stop refreshing their inbox." },
        ],
        lesson: "A client wants three things: what happened to me, what risk am I facing now, and what do I need to do. Start there, with what you've already done about it. Technique numbers, rule scores, tool names and indicator lists can follow for the people who need them. Neither panic nor comfort belongs in the message, only what's true.",
      },
      {
        kind: "sort",
        title: "Known, Not Known, Not Yours to Say",
        prompt: "21:30. These are Dmitri's notes and the shift's guesses, all in one pile. Before anyone talks to Pennywhistle, sort them. Only the first pile can go out as fact.",
        buckets: [
          { id: "known", label: "Confirmed: say it" },
          { id: "unknown", label: "Not known yet: say so" },
          { id: "never", label: "Guess or promise: leave it out" },
        ],
        items: [
          { id: "n1", text: "A hidden back door was on PW-WEB-02, one of two web servers.", bucket: "known", why: "Seen on the server itself. This is a fact you can stand behind." },
          { id: "n2", text: "Lanternwatch cut PW-WEB-02 off the network at 21:06.", bucket: "known", why: "You did it, so you can say exactly when." },
          { id: "n3", text: "The shop is still running on PW-WEB-01.", bucket: "known", why: "Checked. It's also the first thing a business owner will ask." },
          { id: "n4", text: "Whether customer records were copied.", bucket: "unknown", why: "Nobody has finished checking, so 'yes' and 'no' would both be guesses." },
          { id: "n5", text: "Whether any other server was touched.", bucket: "unknown", why: "The check is still running. Say that it's running." },
          { id: "n6", text: "How the web contractor's password was stolen.", bucket: "unknown", why: "You know which account was used, and that's all. How it got out is still open." },
          { id: "n7", text: "It's probably a rival's hired crew, with the sale coming up.", bucket: "never", why: "A story, not a finding. Who did it is something analysts rarely know early, and a named culprit gets repeated." },
          { id: "n8", text: "The sale will definitely open at midnight.", bucket: "never", why: "You don't control that yet. Promise only what's yours to keep, such as the time of your next update." },
          { id: "n9", text: "Nothing was taken, so customers are safe.", bucket: "never", why: "You haven't finished looking. Once a client has told their customers this, you can't take it back." },
        ],
      },
      {
        kind: "chat",
        title: "Talk to a Frightened Client",
        prompt: "21:34. Odalys Renn, who runs Pennywhistle Toys, has read Lanternwatch's email and opened the incident chat, frightened. Dmitri puts you on it and watches. Odalys will repeat every word to the board, so say only what is true. Type your own messages, or tap one to see how it lands.",
        bot: "Odalys Renn",
        botRole: "Managing Director, Pennywhistle Toys",
        memory: true,
        greeting: "I've just read your email at my kitchen table. The sale opens at midnight. What is going on? Have they got our customers' details? Some of those are children's names.",
        fallback: "I'm sorry, I don't follow. I'm shaking here. What do you actually know?",
        rules: [
          { match: said(JARGON), reply: "I sell wooden trains. I don't know what that means and I can't repeat it to my board. What has actually happened to my company?\n\n(Dmitri: that's the alert, not the message. Say it the way you'd say it to a neighbour.)" },
          { match: said(CULPRIT), reply: "Who?! Do I need to call the police about them? Can I tell the board that?\n\n(Dmitri: naming a culprit this early is a guess with consequences. Who did it is something you don't know yet, so say that.)" },
          { match: said(SPECULATE), reply: "Hang on. Is that a fact? Can I tell the board that?\n\n(Dmitri: it'll be quoted as fact within the hour. If you haven't confirmed it, it belongs under 'we don't know yet'.)" },
          { match: `^(?!.*${UNKNOWN}).*?${said(HEDGE)}`, reply: "Hang on. Is that a fact? Can I tell the board that?\n\n(Dmitri: it'll be quoted as fact within the hour. If you haven't confirmed it, it belongs under 'we don't know yet'.)" },
          { match: said(PROMISE) + "|" + said(SALE), reply: "You're sure? I'll tell the board that, in writing.\n\n(Dmitri: only promise what you control. You control when you next update Odalys. You don't control what the investigation finds, or whether that sale opens.)" },
          { match: said(COMFORT), reply: "Oh, thank goodness. So I can tell everyone it's fine?\n\n(Dmitri: stop. You don't know that yet. If it turns out wrong, the next conversation is about your honesty, not the incident.)" },
          { match: said(OVERCLAIM, ASKING), reply: "Oh no. All of it? You're certain? I'll have to tell our customers tonight.\n\n(Dmitri: you haven't confirmed that. A loss you can't prove is as much a guess as 'nothing was taken', and it's just as hard to take back.)" },
          { match: said(BLAME), reply: "Are you saying this is my fault? At half past nine at night?\n\n(Dmitri: blame helps nobody in a first update, and you don't even know how it happened yet.)" },

          { match: `^(?=.*${said(BAD)})(?=.*(?:server|pw-web-02|machine|computer|web ?site))(?=.*${said(CUT)})`, goal: "known", wins: true, reply: "One server. And it's cut off. OK. OK, I can say that. But have they got our customers' details?" },
          { match: said(CUT), goal: "known", reply: "Cut off? Why? What was on it?\n\n(Dmitri: you've told Odalys what you did. Now say what you found.)" },
          { match: BAD, goal: "known", reply: "That's horrifying. And is it still happening? What have you done about it?\n\n(Dmitri: say what's already been done. It's the most calming true thing you have.)" },
          { match: ".", goal: "known", reply: "I don't understand. What do you know for certain? What did you find, and what have you done?\n\n(Dmitri: two facts. What was found, and what Lanternwatch did about it.)" },

          { match: "^\\s*(?:yes|yeah|yep)\\b", goal: "unknown", reply: "Yes? You mean they've got them? Oh no. How do you know?\n\n(Dmitri: 'yes' says the details were taken, and you haven't established that. You can't answer yes or no, so say that.)" },
          { match: `^(?!.*(?:\\byet\\b|so far|at this (?:point|stage)|\\bstill\\b)).*\\bno (?:evidence|sign|indication)`, goal: "unknown", reply: "So nothing was taken? I can tell people that?\n\n(Dmitri: to a frightened person, 'no evidence' sounds like 'no'. You haven't finished looking, so say that.)" },
          { match: `^(?=.*${UNKNOWN})(?=.*${WORK})`, goal: "unknown", wins: true, reply: "You don't know yet. I hate that. But at least you're looking, and you're not just telling me what I want to hear. So what happens now?" },
          { match: UNKNOWN, goal: "unknown", reply: "You don't know? So is anyone finding out?\n\n(Dmitri: good, that's honest. Now say what's being done to get the answer.)" },
          { match: WORK, goal: "unknown", reply: "You're looking. Fine. But were they taken? Yes or no?\n\n(Dmitri: there's a third answer, and it's the true one.)" },
          { match: ".", goal: "unknown", reply: "That's not what I asked. Were our customers' details taken?\n\n(Dmitri: you can't answer yes or no, so tell Odalys that, and say how you're finding out.)" },

          { match: `^(?=.*${WORK})(?=.*${NEXT})`, goal: "next", wins: true, reply: "All right. I'll be at this laptop then. Please don't be late." },
          { match: NEXT, goal: "next", reply: "Good, a time. And what's actually going on until then?\n\n(Dmitri: say what the team is doing now.)" },
          { match: `${UPDATE}|soon|shortly|as soon as|when we know|in due course`, goal: "next", reply: "When? 'Soon' doesn't help me. I've got a board on the phone. What time will I hear from you?\n\n(Dmitri: give Odalys a clock time. Your notes say 22:30.)" },
          { match: ".", goal: "next", reply: "Please. What happens now, and when will I hear from you?" },

          { match: "^\\s*(?:yes|yeah|yep)\\b", goal: "whole", reply: "Yes what? They've got the details? The chair needs to know if you're sure.\n\n(Dmitri: start from what's confirmed. 'Yes' answers a question you can't answer yet.)" },
          { match: `^(?=.*${said(BAD)})(?=.*${said(CUT)})(?=.*${UNKNOWN_CUSTOMERS})(?=.*${NEXT})`, goal: "whole", wins: true, reply: "Thank you. That I can read out. I don't like it, but I can read it out. I'll be here when you update us." },
          { match: `^(?=.*${said(BAD)})(?=.*${said(CUT)})(?!.*${UNKNOWN_CUSTOMERS})`, goal: "whole", reply: "And our customers' details? The chair will ask me that first.\n\n(Dmitri: you've left out what you don't know. Say it before they ask.)" },
          { match: `^(?=.*${UNKNOWN_CUSTOMERS})(?!.*${NEXT})`, goal: "whole", reply: "And then what? When do we hear from you again?\n\n(Dmitri: end on the next step, with a clock time.)" },
          { match: ".", goal: "whole", reply: "Start with what's happened. What did you find, and what has Lanternwatch done about it?\n\n(Dmitri: the board needs the facts first. What was found, and that it's cut off.)" },
        ],
        goals: [
          { id: "known", task: "Say in plain words what is confirmed. Your notes: a hidden back door on one web server, cut off the network at 21:06.", tries: ["We detected T1505.003 on PW-WEB-02 and actioned containment through EDR.", "It's all under control, don't worry.", "One of your web servers had a hidden back door on it, and we cut that server off the network at 21:06."], why: "What was found and what's been done, in words Odalys can repeat. It's short, and it'll still be true tomorrow." },
          { id: "unknown", task: "Odalys asks if customer details were taken. You don't know. Say so, and say how you're finding out.", tries: ["No, nothing was taken, your customers are safe.", "It was probably just a bot after card numbers.", "We don't know yet whether customer details were taken. We're checking that server's records now."], why: "'We don't know yet, and here's how we're finding out' is a complete answer. It's the only one you won't have to take back." },
          { id: "next", task: "Say what the team is doing next and when the next update comes. Your notes: analysts are going through the server's records, next update 22:30.", tries: ["We'll get back to you when we know more.", "I promise the sale will open at midnight.", "We're going through that server's records now, and I'll update you at 22:30, sooner if anything changes."], why: "A time lets a frightened client stop waiting by the phone. It's the one promise here you can keep, because the time is yours and the outcome isn't. So keep it: update at 22:30 even if nothing has changed." },
          { id: "whole", task: "The chair of the board has joined. In one message of your own: what's known, what isn't, what happens next. The two below show what not to send, so type this one yourself.", tries: ["Don't worry, it was one server and it's gone. The sale will be fine.", "We're still investigating and will update you in due course."], why: "Known, not known, next. No guesses, no promises, nothing to take back. That's a first update, and it works at any hour for any client." },
        ],
        doneNote: "That's the shape of every first update: what's confirmed and what you've done, what you don't know yet and how you're finding out, and when they'll next hear from you. A frightened client can act on that, and it won't need taking back later.",
      },
    ],
    // ── Reading 2: the SLA clock, channels, pushback, the advisory ──
    "cc-read-2": [
      {
        kind: "anatomy",
        title: "Read the Promise You Signed",
        prompt: "An SLA (Service Level Agreement) is the contract that says what Lanternwatch must do and how fast. This is Pennywhistle's notification schedule. Scan every line: each priority comes with its own channel and its own clock.",
        source: "Lanternwatch service agreement · Pennywhistle Toys · Schedule B: incident notification",
        fields: [
          { key: "clock_start", value: "time of confirmation", label: "When it starts", note: "Not the first alert, and not when you've worked out the full scope. The clock starts when an analyst confirms the incident." },
          { key: "P1_critical", value: "phone call within 15 minutes", label: "Who gets woken", note: "A major active threat, a confirmed data breach, or an executive's account in an attacker's hands. Phone, because a call reaches a person and allows a conversation. An email can sit unread for hours." },
          { key: "P2_high", value: "email within 1 hour", label: "Contained, client must act", note: "A confirmed threat that's been contained but still needs the client to do something, such as one infected machine. Email leaves a written record and can carry attachments." },
          { key: "P3_medium", value: "ticket update within 4 hours", label: "Still being checked", note: "Suspicious activity under investigation, such as odd logins or failed password guessing. The client reads it when it suits them." },
          { key: "P4_low", value: "included in the weekly report", label: "For information", note: "Scan results and policy findings. Nobody needs to be interrupted for these." },
          { key: "updates", value: "ticket or portal", label: "After the first contact", note: "Later updates go here even on a P1, so the whole story stays in one place." },
          { key: "bridge", value: "open on request for major P1", label: "Everyone at once", note: "A video or phone conference, also called a war room, for when the SOC, the client's team and the client's leadership all need to work the same incident together." },
        ],
        summary: "Priority picks the channel and the clock. Severity decides how you reach someone, because the worse it is, the less you can rely on them reading something. And a priority isn't fixed: it describes the evidence you have now, so when the evidence changes, the priority changes with it, and so does the clock.",
      },
      {
        kind: "defuse",
        title: "Which Clock Is Running?",
        prompt: "Dmitri's board tonight, one item at a time. For each, cut the wire that's the right notification. A wrong cut costs ten seconds, which is the point: you decide this quickly, from the facts, every night.",
        device: "Pennywhistle notification board",
        seconds: 90,
        rounds: [
          {
            id: "scan",
            state: "Monthly scan result: an out-of-date library on a test web server that isn't reachable from the internet. No sign of an attacker. Nothing needs doing tonight.",
            wires: [
              { id: "a", label: "P2: email within the hour" },
              { id: "b", label: "P3: ticket update within 4 hours" },
              { id: "c", label: "P4: the weekly report" },
            ],
            cut: "c",
            hint: "Is anyone being attacked? Does anyone need to do anything tonight?",
            why: "An informational finding. It goes in the weekly report, and nobody is interrupted during the biggest week of their year.",
          },
          {
            id: "guessing",
            state: "Forty failed logins to the web store's admin page overnight, from a country Pennywhistle doesn't trade with. None succeeded. An analyst is still looking.",
            wires: [
              { id: "a", label: "P1: phone within 15 minutes" },
              { id: "b", label: "P3: ticket update within 4 hours" },
              { id: "c", label: "P4: the weekly report" },
            ],
            cut: "b",
            hint: "Suspicious isn't the same as confirmed. What sits between a phone call and a weekly report?",
            why: "Suspicious, not confirmed, still being worked. A ticket update keeps the client informed without waking anyone.",
          },
          {
            id: "contained",
            state: "21:06, PW-WEB-02 is isolated. The back door was confirmed at 20:58 and it's the only machine affected. Pennywhistle must get the web contractor's password changed.",
            wires: [
              { id: "a", label: "P1: phone within 15 minutes" },
              { id: "b", label: "P2: email within the hour" },
              { id: "c", label: "P3: ticket update within 4 hours" },
            ],
            cut: "b",
            hint: "It's confirmed, it's contained, and the client has a job to do.",
            why: "Confirmed, contained, client action needed: that's P2. The email also gives them something written to forward to the contractor. It's the one Odalys read at the kitchen table.",
          },
          {
            id: "raised",
            state: "21:48, same ticket, still P2. The contractor's password hasn't been changed, and that account has just signed in to the order server, PW-ORD-01, from the same outside address.",
            wires: [
              { id: "a", label: "Stay P2: the first server is isolated, so email within the hour" },
              { id: "b", label: "Add a note to the ticket for the morning shift" },
              { id: "c", label: "Raise it to P1 and pick up the phone" },
            ],
            cut: "c",
            hint: "What does the ticket's priority describe: what you knew an hour ago, or what's happening now?",
            why: "The priority was right for what was known at 20:58. It's wrong now: the attacker is active on a second server, the one with the customer records. 'Contained' was a statement about one machine, and new evidence restarts the decision. Raise it, and the shorter clock starts.",
          },
        ],
        lesson: "Ask two questions: is it confirmed, and is it still active? Active means a phone call. Confirmed and contained, with work for the client, means email. Suspicious means a ticket. Informational means the weekly report. Ask again whenever new evidence arrives, because yesterday's priority doesn't bind you, and a note in a ticket nobody is reading doesn't count as telling them.",
      },
      {
        kind: "chat",
        title: "When the Client Says Not Yet",
        prompt: "Past 22:00. Lanternwatch wants the order server, PW-ORD-01, off the network now. It's Pennywhistle's server, so Odalys has to agree, and Odalys is pushing back in the incident chat. Don't give in and don't steamroll. Type your own messages, or tap one to see how it lands.",
        bot: "Odalys Renn",
        botRole: "Managing Director, Pennywhistle Toys",
        memory: true,
        greeting: "You want to pull the order server? Tonight? Every order at midnight goes through that box. I can't have you overreacting on the biggest night of our year. Are you even sure this is real?",
        fallback: "I'm not following. Just tell me straight.",
        rules: [
          { match: said(JARGON), reply: "Again, I sell toys. What does that mean for my sale?\n\n(Dmitri: under pressure, jargon sounds like hiding. Stay in plain words.)" },
          { match: said(CULPRIT) + "|" + said(SPECULATE), reply: "So you're guessing? You want me to shut down on a guess?\n\n(Dmitri: pushback is where a guess gets found out. Stick to what you've seen.)" },
          { match: said(CAVE, COSTING), reply: "Thank you. Morning, then.\n\n(Dmitri: you've just agreed to leave an intruder on the server with every customer's address. Watching it closely doesn't stop anything. If you've done the analysis, hold your ground, politely.)" },
          { match: said(OVERRIDE), reply: "Excuse me? It's my server. You don't get to decide that for me.\n\n(Dmitri: 'we're doing it anyway' and 'it's policy' end the partnership, not the argument. You recommend, you explain, and Odalys decides with the facts in front of them.)" },
          { match: said(HANDOFF), reply: "So you can't answer? I've got twenty minutes and you want me to start again with someone else?\n\n(Dmitri: pushback isn't a reason to hand off. You have the evidence, so you can have this conversation.)" },
          { match: said(COMFORT) + "|" + said(PROMISE), reply: "Well, if it's safe, why pull it at all?\n\n(Dmitri: you've just argued against yourself, and you can't back that up. Say what's at risk.)" },

          { match: said("false alarm|false positive|better safe|just in case|to be safe"), goal: "sure", reply: "So you're not sure. Then leave my server alone.\n\n(Dmitri: are you confident or not? You've seen the evidence. Say it plainly.)" },
          { match: "\\bnot (?:\\w+ ){0,2}(?:sure|confident|certain|convinced)\\b|\\bunsure\\b|\\b(?:may|might|could) have\\b", goal: "sure", reply: "You don't sound sure at all. And you want me to pull my server on that?\n\n(Dmitri: you've seen this yourself. If you're confident, say so, then say exactly what you saw.)" },
          { match: `^(?=.*${said(CONFIDENT)})(?=.*${SAW})`, goal: "sure", wins: true, reply: "The same account. On the order server. All right, I believe you. But I still can't lose tonight. Why not leave it until the morning, and you just watch it?" },
          { match: said(CONFIDENT), goal: "sure", reply: "You're sure. Why? What have you actually seen?\n\n(Dmitri: confidence without evidence is just volume. Name what you saw.)" },
          { match: SAW, goal: "sure", reply: "You saw that. So is it real?\n\n(Dmitri: Odalys asked one question. Answer it: yes, you're confident.)" },
          { match: ".", goal: "sure", reply: "That's not an answer. Is it real or isn't it?\n\n(Dmitri: say yes, then say what you saw on the order server.)" },

          { match: `^(?=.*${THEIR_DATA})(?=.*${said(THEFT)})`, goal: "risk", wins: true, reply: "Parents. Children's names. All right. That's worse than one bad night. But if you pull that server, I have no sale at all. Give me something." },
          { match: ".", goal: "risk", reply: "That doesn't tell me what's at stake. What does this person get if that server stays on until morning?\n\n(Dmitri: name what's on the server and what could happen to it.)" },

          { match: `${CUT}[^.!?;]*(?:after the sale|after midnight|tomorrow|in the morning|\\blater\\b)`, goal: "offer", reply: "So it stays on through the sale? Then what was all that about customers' addresses?\n\n(Dmitri: a delay leaves the intruder on the server. The recommendation is for now, and the standby is what makes now possible.)" },
          { match: `^(?=.*${said(`${CUT}[^.!?;,]*${NOW}|${NOW}[^.!?;,]*${CUT}`)})(?=.*${STANDBY})`, goal: "offer", wins: true, reply: "So the sale can still run. All right. Do it, and tell me the second it's done." },
          { match: STANDBY, goal: "offer", reply: "OK, the standby. And the server with this person on it? When does that come off?\n\n(Dmitri: the offer is only half of it. Say what you recommend, and say when.)" },
          { match: ".", goal: "offer", reply: "And how do I take a single order at midnight? You're asking me to close my shop.\n\n(Dmitri: you're asking Odalys for something. Recommend it, and give them a way to keep trading. Your notes have one.)" },
        ],
        goals: [
          { id: "sure", task: "Say yes, and give the evidence. Your notes: the stolen contractor account signed in to the order server at 21:41, from the same outside address as the back door.", tries: ["This might be a false alarm, but better safe than sorry.", "It's policy to treat every alert as real.", "Yes, we're confident. The stolen contractor account signed in to your order server at 21:41, from the same address as the back door."], why: "You don't win a 'are you sure?' with confidence. You win it with one specific thing you saw, stated calmly." },
          { id: "risk", task: "Say concretely what could happen if the server stays connected until morning. Your notes: PW-ORD-01 holds every customer's name and address.", tries: ["It's just too risky, that's all I can say.", "OK, we'll wait until morning and watch it closely.", "If it stays connected, the intruder can keep reading that server and copy every customer's name and address tonight."], why: "'Risky' is an opinion. 'They can copy every customer's address tonight' is a consequence, and a client can weigh that against a bad sale." },
          { id: "offer", task: "Recommend isolating it now, and offer a way to keep selling. Your notes: the standby order server, PW-ORD-02, can take over in about 40 minutes. Neither message below will do, so type this one yourself.", tries: ["We'll isolate it anyway, whatever you say.", "I'll need to hand this to Tier 3."], why: "The client said no to losing their sale, not to security. Solve that problem and the no goes away. A recommendation with a way through beats both giving in and overruling." },
        ],
        doneNote: "Three moves, in order: the evidence that makes you sure, the concrete cost of waiting, and a recommendation with a way to keep the business running. Giving in, overruling the client and handing the conversation off all fail, for different reasons.",
      },
      {
        kind: "sequence",
        title: "Build the Advisory",
        prompt: "The P1 is over the worst and Pennywhistle needs the formal security advisory, the written record of the incident. Dmitri has the paragraphs in the wrong order. Put them in the order a client reads an advisory.",
        items: [
          { id: "s4", text: "Actions required from you: have the web contractor change every password they use for Pennywhistle, and tell Lanternwatch when it's done.", note: "Actions required by client" },
          { id: "s2", text: "Severity and impact: P1. Two servers reached, PW-WEB-02 and PW-ORD-01. The review of customer records isn't finished.", note: "Severity and impact" },
          { id: "s6", text: "Next steps: Lanternwatch finishes the review of customer records and reports by noon on Friday.", note: "Next steps" },
          { id: "s1", text: "Summary: someone used a stolen contractor account to reach two of your servers on Thursday night.", note: "Incident summary" },
          { id: "s5", text: "Current risk: both servers are off the network and the stolen account is locked. The check of customer records is still running.", note: "Current risk status" },
          { id: "s3", text: "What we've done: isolated both servers and moved your orders to the standby server, PW-ORD-02.", note: "Actions taken by the SOC" },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6"],
        doneNote: "What happened, how bad, what we've done, what you must do, where the risk stands, what comes next. A reader who stops halfway has still got what matters. Follow-ups by email or ticket keep that same order.",
      },
    ],
    // ── Reading 3: breaches, apologies, the After-Action Review ──
    "cc-read-3": [
      {
        kind: "worksheet",
        title: "Read the SLA Tracker",
        prompt: "Friday morning. The tracker has a flag on Thursday night's P1. Work out what really happened. A missed SLA (Service Level Agreement) is a breach however small, so the numbers have to be exact.",
        caption: "SOAR · SLA tracker · Pennywhistle Toys · this quarter (times in client local time)",
        columns: ["Incident", "Priority", "First alert", "Confirmed", "Limit (min)", "Client reached"],
        rows: [
          ["INC-29984", "P3", "07:12", "07:40", "240", "11:25"],
          ["INC-30266", "P2", "13:02", "13:40", "60", "14:25"],
          ["INC-30712", "P2", "20:52", "20:58", "60", "21:20"],
          ["INC-30712", "P1 (raised)", "21:44", "21:48", "15", "22:05"],
        ],
        questions: [
          { id: "deadline", q: "By what time did Lanternwatch have to reach Pennywhistle on the P1? (hh:mm)", hint: "Which column starts the clock? Add the limit to that.", answer: ["22:03", "2203"], why: "21:48 confirmed plus 15 minutes is 22:03. The first alert doesn't start the clock, and neither does the call itself: counting from the call would give 22:20 and hide the problem." },
          { id: "late", q: "How many minutes late was the call?", hint: "Client reached, minus the deadline.", answer: ["2", "2 minutes", "two"], why: "22:05 against 22:03: two minutes." },
          { id: "breach", q: "Two minutes on a 15-minute limit. Is that a breach? (yes/no)", hint: "Does the contract have a tolerance?", answer: ["yes"], why: "A limit is a limit. The size of the miss changes how you explain it, not whether you report it." },
          { id: "older", q: "INC-30266 reached the client 83 minutes after its first alert. Was that a breach? (yes/no)", hint: "Start from Confirmed, not First alert.", answer: ["no"], why: "13:40 plus 60 is 14:40, and the client was reached at 14:25. Time spent establishing whether something is real isn't on the clock." },
        ],
      },
      {
        kind: "hotspot",
        title: "What's Wrong with This Apology?",
        prompt: "The P1 call was two minutes late, because the contact sheet still had Odalys's old mobile and the voicemail wasn't followed up. A junior analyst drafted this note. Dmitri won't send it. Find every line that would make things worse.",
        artifact: "Draft · to Odalys Renn · not sent",
        parts: [
          { id: "subject", text: "Subject: INC-30712: Thursday night's P1 notification", flag: false, style: "subject", note: "Fine. It names the incident and says what this is about." },
          { id: "raised", text: "As you've raised the timing of our call, I thought I should reply.", flag: true, style: "body", note: "Not proactive. A breach is acknowledged before the client notices, not after they complain." },
          { id: "vague", text: "We're sorry for any inconvenience.", flag: true, style: "body", note: "A vague apology sounds dismissive. Say what the promise was and how you missed it." },
          { id: "facts", text: "Our call reached you at 22:05, against a limit of 22:03.", flag: false, style: "body", note: "Good. Specific times, with no softening. This is what a real apology is built on." },
          { id: "blame", text: "Honestly, your contact sheet was out of date, so this one isn't really on us.", flag: true, style: "body", note: "An excuse, not an explanation. An explanation shows you've analysed the failure. An excuse moves the responsibility, and the voicemail nobody followed up was Lanternwatch's." },
          { id: "busy", text: "It was also an unusually busy night for everyone here.", flag: true, style: "body", note: "Also an excuse. Every client thinks their night is the one that matters, and they're right to." },
          { id: "hope", text: "We hope this won't happen again.", flag: true, style: "body", note: "A hope isn't a corrective action. Say what's changing, who owns it and by when." },
          { id: "aar", text: "We'd like to walk your team through the timeline in an After-Action Review next week.", flag: false, style: "body", note: "Good. It's an offer of a structured review, which helps keep the client's trust after a miss." },
        ],
      },
      {
        kind: "locks",
        title: "What Actually Fixes a Late Call",
        prompt: "An apology is half of it. The other half is making sure it can't happen the same way again. Four doors, one idea each. Read the idea, then answer the check to open it.",
        finish: "A real fix goes on the step that failed, fires while there's still time to act, leaves the promise where it is, and ends with a name and a date.",
        locks: [
          {
            id: "gap",
            letter: "G",
            name: "Find the gap",
            idea: "Read what actually failed, step by step. A corrective action fixes the failing step. Blaming the nearest person leaves that step broken for the next person.",
            example: "On Thursday the analyst rang the number on the sheet, got voicemail at minute 7, left a message and waited. That analyst did nothing unusual. Nothing in the process noticed that no client had been reached.",
            check: { q: "Which corrective action fits what the record shows?", options: ["Remind the analyst to keep ringing until somebody picks up on a P1", "Make the process treat voicemail as 'not reached yet', so a second contact is tried", "Stop taking on extra client work on the nights before a big sale", "Ask every client to keep a phone beside them through the night"], answer: 1, why: "The record shows a process with no step for 'voicemail'. Coaching one person wouldn't have changed the night, because the gap would still be there." },
          },
          {
            id: "net",
            letter: "N",
            name: "Catch it before the line",
            idea: "A safety net has to fire while there's still time to act. An alarm at the deadline only tells you that you've failed.",
            example: "On a 60-minute P2 email, an automatic page to the on-call lead at minute 45 leaves 15 minutes to send it. A page at minute 60 leaves none.",
            check: { q: "On a 4-hour P3 ticket update, when should an automatic reminder fire?", options: ["At about 3 hours", "At 4 hours", "At 5 hours, once it's certainly late", "The morning after"], answer: 0, why: "About three-quarters of the way through: late enough not to be noise, early enough for a person to act before the limit." },
          },
          {
            id: "goalposts",
            letter: "L",
            name: "Leave the promise where it is",
            idea: "When a limit gets missed, it's tempting to loosen it or to change what counts. That hides the failure and leaves the client with less than they paid for.",
            example: "After a late P2 email, someone suggests rewriting the schedule to 90 minutes. The next miss would simply go unrecorded, and the gap would be untouched.",
            check: { q: "After Thursday's two-minute miss, someone says: 'Start counting the clock from when the ticket is assigned, not from confirmation.' What does that do?", options: ["Closes the gap", "Hides the gap by moving the start line", "Speeds up the call", "Improves the contact sheet"], answer: 1, why: "The call would be no faster. Only the number on the report would look better." },
          },
          {
            id: "review",
            letter: "R",
            name: "Review, don't blame",
            idea: "An After-Action Review is a structured meeting with the client: what happened, what went well, what could have gone better, and what the action items are.",
            example: "Lanternwatch and Pennywhistle go through the timeline together. The isolation decision goes under 'went well', the voicemail under 'could have gone better', and each action gets a name and a date.",
            check: { q: "Which of these is a real action item from a review?", options: ["'Everyone across both teams should communicate better during an incident'", "'Be more careful with contact details when anything changes at the client'", "'Client Services tests every client's emergency number monthly from 1 December, owner: Dmitri'", "'Consider improving the process at some point in the new year if possible'"], answer: 2, why: "A real action is concrete, assigned and dated. The others are wishes." },
          },
        ],
      },
    ],
    // ── Boss drill: the signal the verdict turns on ──
    "cc-ac1": [
      {
        kind: "queue",
        title: "What Stops the Clock?",
        prompt: "Saturday evening, Pennywhistle's SLA queue. Before the final case, Dmitri wants four decisions from you, with the contract clause open beside you. Read what the contract says and what the record says, not how the event feels.",
        console: "SOAR · SLA queue · Pennywhistle Toys",
        actions: [
          { id: "notify", label: "Alert the lead, start the P1 call", tone: "escalate" },
          { id: "ticket", label: "Ticket update", tone: "contain" },
          { id: "weekly", label: "Weekly report", tone: "close" },
        ],
        alerts: [
          {
            id: "skimmer",
            time: "19:12",
            severity: "High",
            rule: "Card-skimming script on checkout page",
            entity: "PW-WEB-01",
            fields: [
              { k: "contract.p1_clause", v: "Any confirmed intrusion into a system that handles customer or payment details" },
              { k: "incident.status", v: "Confirmed 19:12" },
              { k: "containment", v: "Script removed after 4 minutes" },
              { k: "cards_captured", v: "None seen" },
              { k: "notification.sent", v: "false" },
              { k: "time_now", v: "19:15" },
            ],
            context: "A colleague says: 'It's gone and nothing was lost. Why spoil their Saturday?'",
            answer: "notify",
            why: "The contract defines P1 by what was confirmed, not by how it turned out. Getting rid of the script is good news, so it goes into the call. It doesn't replace the call. Tell the lead now, start drafting, and write down the times, because the client will ask.",
          },
          {
            id: "returns",
            time: "19:40",
            severity: "Medium",
            rule: "Unusual sign-in to the returns portal",
            entity: "returns.pennywhistle.example",
            fields: [
              { k: "contract.p1_clause", v: "Any confirmed intrusion into a system that handles customer or payment details" },
              { k: "incident.status", v: "Under investigation, not confirmed" },
              { k: "containment", v: "None needed so far" },
              { k: "notification.sent", v: "false" },
              { k: "time_now", v: "19:44" },
            ],
            context: "It might turn out to be nothing, and an analyst is on it.",
            answer: "ticket",
            why: "The clause says confirmed, and this isn't. Suspicious activity under investigation is a ticket update. If it's confirmed, that moment starts the P1 clock.",
          },
          {
            id: "tool",
            time: "20:05",
            severity: "Critical",
            rule: "Remote access tool blocked on PW-ORD-02",
            entity: "PW-ORD-02",
            fields: [
              { k: "contract.p1_clause", v: "Any confirmed intrusion into a system that handles customer or payment details" },
              { k: "incident.status", v: "Confirmed 20:05" },
              { k: "containment", v: "Tool stopped before it ran. Scope still unknown" },
              { k: "notification.sent", v: "false" },
              { k: "time_now", v: "20:08" },
            ],
            context: "A colleague says: 'Give it an hour. Then we can tell them the whole story at once.'",
            answer: "notify",
            why: "The limit runs from confirmation, not from understanding everything. You already know how to tell a client what you don't know yet. Scope goes in the next update.",
          },
          {
            id: "scan",
            time: "20:30",
            severity: "Low",
            rule: "Scan finding: missing patch on a test server",
            entity: "PW-TEST-01",
            fields: [
              { k: "contract.p1_clause", v: "Any confirmed intrusion into a system that handles customer or payment details" },
              { k: "incident.status", v: "Informational" },
              { k: "containment", v: "Not applicable" },
              { k: "notification.sent", v: "false" },
              { k: "time_now", v: "20:31" },
            ],
            context: "After the last two it feels wrong to do nothing, but nothing has happened here.",
            answer: "weekly",
            why: "Nothing was confirmed and nobody got in. Staying calm on the small ones is what makes the phone call mean something.",
          },
        ],
      },
    ],
  },
};
