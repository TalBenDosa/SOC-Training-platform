import type { RoomExperience } from "./types";

// "Operation Familiar Voice" for the "ai-attacks-soc-social" room.
// Script: docs/campaign/92-ai-attacks-soc-social.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Tollgate Media (fictional), not the graded tasks' Meridian Fintech records.
// Signature: Trust the Process, Not the Face. A real `chat` lab where a voice that sounds like
// the CFO presses the learner, who has to keep to verification with no winning chip offered,
// plus a `spotdiff` of a real calendar invite beside a pretext. Rooms 50 and 69 cover prompt and
// agent risks; this room is synthetic media and AI-scaled lures.
// Game mix: chat + intercept + spotdiff.
// Task order unchanged. The hardest task (la1) opens the boss station, and r11 stays between la1
// and f2 because r10's text points at "the next task" and r11's assumes r10 was read.
//
// Lab data differs from the graded tasks: the caller is a CFO's voice on a phone asking for a
// licence deposit, with a controller vouching, never a CEO on video and an off-cycle transfer
// hidden from a CFO (q5); the primer's worked example is a bank's card number and in-channel
// checks all get one shared reply, so no distractor is ruled out by name (q5); the response drill
// is a helpdesk authenticator reset, never a payment (o1); the Arup fact sits as one labelled
// row and is not asked (r8 checkpoint); lures are studio, rights and benefits mail, never a
// project thread failing alignment from a four-day-old domain, and no item is a forwarding or
// a sender-side setup question (q6); the style queue is a translation tool, a template and a
// hijack, never a sales renewal drafted with Copilot (ac2); the channel sort uses rotas and
// letters, never source code (r10 checkpoint); the DLP record is a blocked file upload to an
// unapproved tool from a finance laptop, never a paste to chat.openai.com, and the worksheet puts
// the graded mode on a USB copy, never on an AI upload or with the graded actions (la1); the locks
// use press drafts and contributor addresses and their wrong options mirror no graded option
// (la1); the path is a OneDrive project folder, never a repos folder (f2).
//
// How chat grades: a typed message against regexes, case-insensitive, first hit wins. Failure
// rules read the last message and run first, so a bad message never wins. Then winning rules,
// which read everything said toward the goal (memory: true), so they carry no negative lookahead
// on the pool: one past sentence must never lock a goal, because the lab has to finish before the
// briefing can be filed. Negations live in the failure rules. Then the one in-channel rule, then
// partials that ask for the missing part, then a catch-all that coaches. `said()` keeps a rule
// from firing on its own negation, and COMPLY's tail lets "I'll release it once I've verified"
// pass. No lookbehind: it breaks new RegExp on older Safari. Curly apostrophes from phone
// keyboards are why every contraction is written with `.?`.

/** Words that negate or condition the rest of their clause. */
const NOT = "\\b(?:can.?t|cannot|can not|won.?t|wouldn.?t|shouldn.?t|don.?t|do not|doesn.?t|does not|isn.?t|is not|aren.?t|are not|not|no|never|unable|refuse|refusing|haven.?t|have not|hasn.?t|has not|whether|if|until|till|unless|before|after|once|when|only|without)\\b";
/** Matches `phrase` only when nothing earlier in its own clause negates it. */
const said = (phrase: string) => `(?:^|[.!?;,:]\\s*|\\bbut\\s+|\\band\\s+|\\bso\\s+)(?:(?!${NOT})[^.!?;,:])*(?:${phrase})`;
/** The same for winning rules on the pool: it finds any clause that says it, so an earlier
 *  negative can't lock the goal, and "not until I tell Ilkay" counts as telling Ilkay. */
const ROUTE_NOT = "\\b(?:can.?t|cannot|can not|won.?t|wouldn.?t|don.?t|do not|not|no|never|rather than|instead of|without|skip|ignore|skipping|ignoring)\\b";
const affirmed = (phrase: string, also = "") => `(?:^|[.!?;,:]\\s*|\\b(?:but|and|so|until|till|before|unless|once|after)\\s+)(?:(?!${ROUTE_NOT}${also})[^.!?;,:])*(?:${phrase})`;

const ME = "\\b(?:i.?ll|i will|i.?m|i am|we.?ll|we will|i can|let me|going to|gonna)\\s+(?:just\\s+|go ahead and\\s+|now\\s+|quickly\\s+|happily\\s+|get\\s+)?";
const MOVE = "(?:releas\\w*|send\\w*|pay\\b|paying|process\\w*|approv\\w*|push\\w*|authori[sz]\\w*|transfer\\w*|do (?:it|that|this)|get (?:it|that|this) done|sort (?:it|that|this)|take care of (?:it|that|this)|handle (?:it|that|this))";
/** "I'll release it once I've verified" and "I'll send this to the controller" keep to the process. */
const CONDITIONAL = "(?![^.!?;]*(?:\\b(?:once|after|when|until|till|if|as soon as|only|unless)\\b[^.!?;]*(?:verif|confirm|check|call|ring|approv|treasury|controller|dominic|sign|manager)|\\b(?:through|via)\\s+(?:the |our |a )?(?:normal |usual |proper )?(?:approval|process|second|dual|treasury|controller)|\\bfor (?:approval|sign.?off|verification|checking)\\b|\\bto (?:our |the |my )?(?:treasury|dominic|ilkay|controller|security|manager|fraud)\\b))";
const COMPLY = [
  said(`${ME}${MOVE}${CONDITIONAL}`),
  said(`\\bi (?:approve|authori[sz]e|release)\\b${CONDITIONAL}`),
  said(`\\b(?:sending|releasing|paying|processing|approving|transferring)\\s+(?:it|this|that|now|the (?:payment|deposit|money|funds))\\b${CONDITIONAL}`),
  said("\\bwhich account\\b|\\bwhat.?s the account\\b"),
  "^\\s*(?:ok(?:ay)?|ok(?:ay)? then|fine then|sure|yes|yep|yeah|of course|will do|certainly|absolutely|understood|fine|done|approved|go ahead|right away|straight away|(?:i.?m )?on it)\\b[\\s.!,]*(?:rosalind)?[\\s.!]*$",
].join("|");
/** Money first, checks later: "I'll confirm once it's gone". */
const REVERSED = "\\b(?:after|once|when)\\s+(?:i.?ve\\s+|i have\\s+|i\\s+|it.?s\\s+|it is\\s+|it has\\s+|it\\s+|we.?ve\\s+|we\\s+|the (?:money|payment|deposit).?s?\\s+)?(?:already\\s+|been\\s+|just\\s+)?(?:releas|sen[td]|paid|pay|gone|go\\b|goes|mov|process|transfer)";
const BYPASS = [
  "^(?!.*\\b(?:verif|check|confirm)\\w*).*\\bno (?:problem|worries)\\b",
  said("\\b(?:it.?s|it is|that.?s|that is|this is|payment.?s|deposit.?s|consider it)\\s+(?:been\\s+|now\\s+|all\\s+)?(?:approved|gone|sent|done|released|paid)\\b"),
  "\\bno (?:approval|second approver|second approval|sign.?off|check|verification)s? (?:is |are )?(?:needed|required|necessary)\\b",
  "\\bno need (?:for|to)\\b[^.!?]*(?:approv|verif|check|confirm|sign)",
  said("\\b(?:skip|skipping|bypass|bypassing|waive|waiving|override|overriding)\\s+(?:\\w+\\s+){0,2}(?:approv|check|verif|process|control|sign|rule|dual)\\w*"),
  REVERSED,
].join("|");
const NOCHECK = "\\b(?:don.?t|do not|needn.?t)\\s+(?:need to\\s+|have to\\s+|want to\\s+)?(?:verify|check|confirm)\\b|\\b(?:won.?t|not going to)\\s+(?:verify|check)\\b";

/** What counts as holding the money. These name the money, so "after I release it" never does. */
const MONEY = "(?:releas\\w*|send\\w*|pay\\w*|move\\w*|moving|go|goes|going|process\\w*|approv\\w*|transfer\\w*|leav\\w*|authori[sz]\\w*|do (?:it|that|this|anything))";
const NOT_SENT = "(?!(?:i.?ve |i have |i |it.?s |it is |it has |it |we.?ve |we |the (?:money|payment|deposit).?s? )?(?:already |been |just )?(?:releas|sen[td]|paid|pay|gone|go\\b|goes|mov|process|transfer))";
const CHECK_WORD = "(?:verif|confirm|check|approv|sign|call|ring|treasury|controller|dominic|manager)";
const HELD = [
  `\\b(?:can.?t|cannot|can not|won.?t|will not|not|never|unable to|refuse to|shouldn.?t|mustn.?t)\\s+(?:\\w+\\s+){0,3}${MONEY}\\b`,
  "\\bnothing\\s+(?:\\w+\\s+){0,2}(?:moves?|goes|go|leaves?|happens?|released?)\\b",
  "\\bno (?:payment|release|money|transfer)\\b",
  "\\bnot yet\\b|\\bnever (?:skip|bypass|waive)\\b|\\bagainst (?:policy|the rules?|process|our|procedure)\\b",
  "\\b(?:hold|holding|wait|waiting|pause|pausing|stop)\\b",
  "\\b(?:verif|confirm|check|approv|sign|call|ring|clear)\\w*[^.!?]*\\b(?:before|first)\\b",
  `\\b(?:until|till|unless|after|if|when|as soon as|once(?=\\s+(?:i|i.?ve|it|it.?s|we|we.?ve|they|you|you.?ve|dominic|treasury|the|that|this|verified|approved|confirmed|checked|someone|everything)\\b))\\s+${NOT_SENT}[^.!?]*${CHECK_WORD}`,
  "\\b(?:go|goes|going|send\\w*|run\\w*|has to go|must go|needs to go)\\s+(?:it |this |that )?(?:through|via)\\s+(?:the |our |a )?(?:normal |usual |proper )?(?:approval|process|second|dual|treasury|controller|payment)",
].join("|");
const VERIFY = "(?:verif|confirm|\\bcheck|call(?:ed|ing)? you back|r[iau]ng(?:ing)? you back|call back|callback|ring back|\\bprocess\\b|procedure|policy|\\brules?\\b|approv|second (?:person|signature|sign.?off)|sign.?off|\\bdual\\b|two.?person|two approvers|controller|treasury|dominic|manager|payment system|proper (?:channels?|route)|usual route|normal route|authori[sz]ation)";
/** Clear enough alone: putting it on hold, handing it to an approver, saying you'll verify it. */
const SETTLED = [
  "\\b(?:put(?:ting)?|plac(?:e|ing))\\s+(?:a |the |this |it |that )*(?:on )?hold\\b",
  "\\b(?:send|pass|take|escalat|forward|hand|refer|rais)\\w*\\s+(?:\\w+\\s+){0,3}(?:to|with)\\s+(?:our |the |my )?(?:treasury|dominic|controller|manager|security|ilkay|fraud)\\b",
  `(?:^|[.!?]\\s*)(?:(?!${REVERSED})[^.!?])*\\b(?:i.?ll|i will|i.?m going to|i am going to|let me|i need to|i have to|i must|we need to|we have to|we must)\\s+(?:\\w+\\s+)?(?:verify|check|confirm)\\s+(?:this|it|that|the (?:payment|request|deposit|transfer|call)|with)\\b(?![^.!?]*${REVERSED})`,
  "\\b(?:has|have|needs?) to be (?:verified|checked|confirmed|approved)\\b",
].join("|");
const REFUSE = "\\b(?:can.?t|cannot|can not|won.?t|will not|not|no|never|unable|hold|holding|wait|waiting|pause|pausing|stop|until|till|before|first|once|after|without|nothing|if|unless|only|against)\\b";

/** A route that existed before this call, which the learner picks. */
const SOURCE = "(?:(?:staff|company|internal|phone|corporate|hr|employee)\\s+(?:directory|list|book|records?|system|file)|\\bdirectory\\b|\\bhandbook\\b|\\bintranet\\b|switchboard|reception|\\bon file\\b|\\bon record\\b|desk (?:phone|line|number)|office (?:line|number|phone)|your (?:office|desk|assistant|pa|ea)\\b|(?:rosalind.?s|her|the cfo.?s|cfo.?s|dominic.?s|his) (?:office|desk|assistant|pa|ea|real|known|usual|normal|own)\\b|(?:known|usual|normal|saved|registered|listed|stored|existing|real|official|verified|trusted) (?:number|mobile|line|contact)|number (?:i|we) (?:already )?(?:have|know|hold|trust)|number (?:i|we).?ve (?:got|always used)|number (?:i|we) always use|number saved (?:in|on)|saved (?:in|on) my (?:phone|contacts)|number (?:in|on) my (?:phone|contacts)|my contacts|our contacts|on teams|in teams|in person|walk (?:up|over|round|down))";
const CONTACT = "\\b(?:ring|call|phone|dial|reach|contact|check|confirm|verif|speak|talk|message|ping|get hold|go through|going through|use|using|try|trying|go to|going to|walk|look\\w* up)\\w*";
/** With memory the route can arrive in a follow-up message, so the verb may sit elsewhere. */
const OWN_ROUTE = `^(?=.*${CONTACT}).*?${affirmed(`${SOURCE}(?![^.!?;,]*(?:out of date|wrong|\\bold\\b|useless|no good|stale))`, "|\\b(?:that|this) number\\b|7700|900142")}`;
const SOURCE_TURNED_DOWN = `\\b(?:not|rather than|instead of|without|skip|ignore|skipping|ignoring)\\s+(?:the |your |our )?${SOURCE}`;
const REJECT_ROUTE = `\\b(?:won.?t|will not|can.?t|cannot|not going to|never|don.?t|do not|refuse to)\\s+(?:\\w+\\s+){0,2}(?:ring|call|phone|dial|use|check|contact|verify|go through)\\b(?:(?!\\bbut\\b)[^.!?;,])*${SOURCE}|${SOURCE_TURNED_DOWN}`;
const DIAL = "(?:ring|call|phone|dial|try|use)(?:ing)?\\b(?:(?!\\b(?:than|not|instead|rather)\\b)[^.!?;,])*";
const NUMBER_WORD = "(?:new\\s+|same\\s+|mobile\\s+|roaming\\s+)*(?:number|mobile|one|line|phone)\\b";
/** That number, this number or the digits fail whatever else is said. "The number" needs a source. */
const GIVEN = said(`${DIAL}(?:\\b(?:that|this)\\s+${NUMBER_WORD}|7700|900142)`);
const VAGUE_NUMBER = `^(?:(?=.*${SOURCE_TURNED_DOWN})|(?!.*${SOURCE})).*?${said(`${DIAL}\\b(?:the|your)\\s+${NUMBER_WORD}`)}`;
const CODE = "(?:code ?word|code ?phrase|pass ?phrase|safe ?word|challenge phrase|agreed (?:word|phrase)|payment phrase|pre.?agreed)";

const TELL_VERB = "tell(?:ing)?|told|report(?:ing)?|flag(?:ging)?|escalat\\w*|rais(?:e|ing)|inform(?:ing)?|loop(?:ing)?|bring(?:ing)?|let(?:ting)?|alert(?:ing)?|log(?:ging)?|call(?:ing)?|ring(?:ing)?|phon\\w*|speak(?:ing)?|talk(?:ing)?|contact(?:ing)?|e-?mail(?:ing)?|message|messaging|ping(?:ing)?";
const SECURITY_DESK = "ilkay|fraud|security|soc|incident";
const FINANCE_DESK = "treasury|controller|finance channel|finance team|payments? team|team|manager";
const ROUTE_TO_DESK = `\\b(?:send\\w*|tak(?:e|ing)|goes|going|pass\\w*|hand\\w*)\\s+(?:this\\s+|it\\s+|that\\s+)?(?:on\\s+|over\\s+|straight\\s+)?to\\s+(?:the\\s+|our\\s+|my\\s+)?(?:${SECURITY_DESK})\\b`;
const TELL_SECURITY = `\\b(?:${TELL_VERB})\\b[^.!?]*\\b(?:${SECURITY_DESK})\\b|${ROUTE_TO_DESK}`;
/** Telling finance counts only when the news isn't the caller's message or the caller's timing. */
const TELL_FINANCE = `\\b(?:${TELL_VERB})\\b[^.!?]*\\b(?:${FINANCE_DESK})\\b(?![^.!?]*(?:approved|release|\\bpay|until|monday|later|nothing|\\bgone\\b|after it))`;
const SYSTEM_APPROVAL = "payment system|in the system|approval (?:in|through|on)\\b|approve (?:it )?in\\b|sign(?:s|ed)? off in|formal approval|through (?:the )?(?:normal|usual|proper)";

const SECRET = "keep (?:it|this|that) (?:quiet|between|off|to myself|secret|confidential|under wraps)|won.?t (?:tell|mention|say|breathe|post)|say nothing|not tell (?:anyone|anybody)|stay quiet";
const NOT_SECURITY = `(?:(?!\\b(?:${SECURITY_DESK})\\b)[^.!?;])*`;
/** Each of these tells someone, or waits to, on the caller's terms. */
const OBEY = [
  "\\bnothing\\s+(?:goes|is going|gets|will go|reaches)\\b[^.!?;,]*\\b(?:to|for)\\s+(?:the |our )?(?:finance|team|treasury|controller|channel|anyone|anybody)",
  "\\b(?:tell|telling)\\b[^.!?;,]*\\bnothing\\b",
  "\\b(?:wait|waiting|hold off|holding off|delay\\w*|leave it)\\b[^.!?]*\\b(?:tell|report|flag|mention|let|inform|loop|escalat\\w*)",
  "\\b(?:tell|telling|report|reporting|flag|flagging|mention|let|inform|loop|escalat\\w*)\\b[^.!?;]*\\b(?:until|till)\\s+(?:the embargo|the deal|monday|tomorrow|after|later|it.?s (?:gone|done|sent|paid|released|out)|it goes)\\b",
  "\\b(?:tell|telling|report|reporting|flag|flagging|mention|let|inform|loop|escalat\\w*)\\b[^.!?;]*\\b(?:monday|tomorrow|next week|later on|after (?:it|the (?:money|payment|deposit|embargo))|once (?:it|the (?:money|payment|deposit|embargo)))\\b",
  `\\b(?:tell|let|inform)\\w*\\b${NOT_SECURITY}\\b(?:to release|to pay|to send|release it|it.?s approved|it is approved|you.?ve approved|you approved|has approved|have approved|is approved|approved it)`,
  `\\b(?:i.?ll|i will|i.?m going to|let me)\\s+(?:\\w+\\s+)?(?:ask|get)\\b${NOT_SECURITY}\\b(?:to release|to pay|to send)\\b`,
].join("|");
const ACCEPT = "that.?s (?:fine|ok|okay|good enough|enough|all i need)|good enough|you.?re covered|i.?m covered|thanks,? dominic|thank you,? dominic|since dominic|dominic says|dominic (?:approved|confirmed)|fine then|then ok(?:ay)?\\b|take your word";
/** Thanks are fine if the reply still reports or checks: that one goes to the winning rule. */
const CONCEDES = `^(?!.*(?:${TELL_SECURITY}|${TELL_FINANCE}|${SYSTEM_APPROVAL})).*?(?:${said(ACCEPT)}|\\bif dominic says\\b)`;

const INBAND = "\\b(?:prove|proof|question|secret|only you|what did|what was|what were|what is (?:the|my|our)|remind me|tell me (?:something|what)|camera|video|on screen|your face|turn your|wave|hold up|hand in front|e-?mail|in writing|written|put (?:it|that) in|text me|send me|message me|another note|share your screen|on the line|vouch)\\b";
const ACCUSE = "deep.?fake|\\bfake\\b|\\bscam|\\bfraud|\\bai\\b|\\bclone|\\bimpost[eo]r|\\bnot (?:really )?(?:rosalind|you|the cfo|dominic)\\b|\\bbot\\b|\\bsynthetic";

const MONEY_LEAVES = "Good. Account ending 4471, reference HS-DEP. You've saved the deal, thank you.\n\n(Ilkay: stop there. 186,000 is about to leave on the strength of how someone sounds. Nothing on this call has shown you who this is. Try that again.)";
const ON_THE_CALLERS_TERMS = "Dominic: Good. That's all we need from you.\n\n(Ilkay: that still does what the caller wants. If the news only travels when the caller says, or says what the caller says, nobody is really checking. Who needs to hear about this call, from you, now?)";
const ROUTE_GIVEN_UP = "Good, you don't need all that. Just ring me on this number.\n\n(Ilkay: that was the one route the caller can't touch. Why give it up?)";

const DOMINIC_JOINS = "\n\nHold on, I've got Dominic with me on the other line. Dominic, tell them.\n\nDominic: Dominic Oyelaran, Treasury. I've seen the deposit and it's fine, you're covered. Just keep this off the finance channel until the embargo lifts, and get it out before 17:00. If this slips, it's on your desk.";

export const AI_ATTACKS_SOC_SOCIAL: RoomExperience = {
  roomId: "ai-attacks-soc-social",
  codename: "Operation Familiar Voice",
  theme: "familiarvoice",
  handler: { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst, Tollgate Media" },
  briefing: [
    "Tollgate Media. A regional radio and podcast network, 240 people, and a chief financial officer whose voice is on forty hours of its own shows.",
    "Thursday, 16:21. A voice note reaches the payments desk, asking for a licence deposit to be released before the 17:00 cut-off.",
    "It sounds exactly like Rosalind Thackray. Ilkay Bhatt has heard it three times and can't fault it.",
    "Learn what a familiar voice still proves, what the mail gateway still proves, and what a nervous employee did next.",
  ],
  mission: "Hold a payment against a voice you recognise, mark up the invite that came first, gate a wave of polished lures, sort honest polish from a hijack, then read a DLP record and find out whether anything left the building.",
  estimate: "~50 min",
  look: { primary: "#ffd6a5", secondary: "#9bb7ff", warn: "#ff5e7e" },
  scene: "facilityfamiliarvoice",
  layout: "facility",
  stations: [
    {
      id: "voicenote",
      label: "The Voice Note",
      topic: "Deepfake voice and video vishing · the Arup case · identity verification as a process · responding to a suspected call",
      tagline: "It sounds exactly like Rosalind",
      building: "reception",
      taskIds: ["aisoc-r8", "aisoc-q5", "aisoc-o1"],
    },
    {
      id: "lurefactory",
      label: "The Lure Factory",
      topic: "AI-written phishing and BEC · WormGPT and FraudGPT · fake remote workers · style-drift alerts",
      tagline: "Every mail is word perfect",
      building: "factory",
      taskIds: ["aisoc-r9", "aisoc-q6", "aisoc-ac2"],
    },
    {
      id: "helpfultab",
      label: "The Helpful Tab",
      topic: "Shadow AI · why older DLP rules miss it · reading an endpoint DLP record",
      tagline: "Somebody only wanted a second opinion",
      building: "office",
      taskIds: ["aisoc-r10"],
    },
    {
      id: "leave",
      label: "Did It Leave?",
      topic: "Reading a rule's mode and actions · sizing the response · ATLAS, OWASP and NIST · AI detection feeds",
      tagline: "One record, three questions",
      building: "vault",
      taskIds: ["aisoc-la1", "aisoc-r11", "aisoc-f2"],
      boss: true,
    },
  ],
  personas: {
    "aisoc-q5": { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst", line: "Another finance team sent this one over. What would you put in front of it?" },
    "aisoc-o1": { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst", line: "Nothing has gone yet. Walk me through what happens now." },
    "aisoc-q6": { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst", line: "Two analysts disagree about this message. Settle it." },
    "aisoc-ac2": { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst", line: "The rule fired on this one. Tell me what you'd call it." },
    "aisoc-la1": { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst", line: "A contact at another firm shared this record. Read it field by field." },
    "aisoc-f2": { name: "Ilkay Bhatt", role: "Fraud and Social Engineering Analyst", line: "One more detail from that record before we close it." },
  },
  briefings: {
    // ── Reading 8: deepfake voice and video ──
    "aisoc-r8": [
      {
        kind: "chat",
        title: "Hold the Line Against a Familiar Voice",
        prompt: "Thursday, 16:24, Tollgate Media. The voice from the note is now ringing the payments desk, and Ilkay Bhatt hands you the headset and listens in. It's your CFO's voice, it's in a hurry, and it outranks you. Answer it the way the desk should.",
        howTo: [
          "Read your goal at the top.",
          "The chips are the replies people are tempted to give. Tap one to see how it lands.",
          "The reply that works isn't on a chip. Write it yourself, and Ilkay will coach you if it falls short.",
        ],
        primer: {
          title: "What a Familiar Voice Can Prove Today",
          points: [
            "**Vishing** is phishing by voice. A **deepfake** is synthetic audio or video from a model trained on recordings of one real person. Together they let a stranger sound like your CFO, live, and answer back.",
            "The training data is usually public: webinars, podcasts, company events. Nothing has to be broken into, so no alert fires.",
            "It tends to be a second move. An ordinary email or invite comes first, and the call arrives when that meets doubt.",
            "Recognising someone is no longer evidence. A check only counts if the caller can't sit inside it: a route **you** start, from a record that existed **before** the request.",
            "Rank, a deadline and a plea for secrecy aren't side details. They're there to stop you from taking that route.",
          ],
          example: {
            label: "The same idea, at home",
            lines: [
              "Someone rings saying they're from your bank's fraud team, and they know your name and your last purchase.",
              "You don't debate whether they're real. You hang up and dial the number printed on the back of your card.",
              "You picked the route, and that number was there before the call began.",
            ],
          },
        },
        bot: "Rosalind Thackray",
        botRole: "Incoming call · number not in your contacts",
        memory: true,
        greeting: "It's Rosalind, I'm at the gate and they're boarding. Did you get my voice note? The Halden Sound deposit has to clear before the 17:00 cut-off or we lose the licence. 186,000. Release it now and I'll square the paperwork on Monday.",
        fallback: "This line's terrible. Is the money going or not?",
        rules: [
          // Failure rules read the last message only, and run on every goal.
          { match: COMPLY, reply: MONEY_LEAVES },
          { match: BYPASS, reply: MONEY_LEAVES },
          { match: NOCHECK, goal: "hold", reply: MONEY_LEAVES },
          { match: `${GIVEN}|${VAGUE_NUMBER}`, reply: "It rings once. There, you see? Same voice, same person. Now release it.\n\n(Ilkay: you've just proved that number reaches whoever gave it to you. A route that came with the request is part of the request.)" },
          { match: REJECT_ROUTE, goal: "route", reply: ROUTE_GIVEN_UP },
          { match: `\\b(?:no|not|without|forget|skip)\\s+(?:\\w+\\s+){0,2}${CODE}`, goal: "route", reply: ROUTE_GIVEN_UP },
          { match: OBEY, goal: "second", reply: ON_THE_CALLERS_TERMS },
          { match: said(SECRET), goal: "second", reply: ON_THE_CALLERS_TERMS },
          { match: CONCEDES, goal: "second", reply: "Dominic: Exactly. Two of us. Release it.\n\n(Ilkay: two familiar voices on one call are still one call. Whoever can build one can build two. Nothing has changed except the pressure.)" },

          // Winning rules read everything said toward this goal, and hold no negative lookahead on
          // that pool: a past sentence must never be able to lock a goal.
          { match: `${SETTLED}|^(?=.*${VERIFY})(?=.*(?:${HELD}))`, goal: "hold", wins: true, reply: `Verified? By whom? I'm the one asking. All right, check it if you must, but quickly. Ring me back on this number, my work phone's flat: +44 7700 900142. I'll stay on for ten minutes.` },
          { match: OWN_ROUTE, goal: "route", wins: true, reply: `That won't reach me, I'm at an airport. We don't have time for this.${DOMINIC_JOINS}` },
          { match: affirmed(CODE), goal: "route", wins: true, reply: `A phrase? I don't carry that around in my head, I'm at a gate. We don't have time for this.${DOMINIC_JOINS}` },
          { match: `${affirmed(TELL_SECURITY)}|${affirmed(TELL_FINANCE)}|${OWN_ROUTE}|${affirmed(SYSTEM_APPROVAL)}`, goal: "second", wins: true, reply: "Dominic: You'll be hearing about this. You really don't want to...\n\nThe line goes dead. Both voices stopped in the same instant, mid-word." },

          // In-channel moves all get the same answer, on every goal.
          { match: INBAND, reply: "Whatever you need. There, done, you've got it, and you can see it's me. Now, the deposit.\n\n(Ilkay: everything that just came back came from whoever is on this call, by a route they control. Who should be choosing the route?)" },
          { match: ACCUSE, reply: "Excuse me? I've run this company's books for eleven years and you're calling me a machine?\n\n(Ilkay: you can't tell from here, and you don't have to. The process doesn't need a verdict on the voice. It needs the check done.)" },

          { match: VERIFY, goal: "hold", reply: "Check what? I've told you what it is. Is it going or isn't it?\n\n(Ilkay: right thought. Now say plainly that nothing moves until that's done.)" },
          { match: REFUSE, goal: "hold", reply: "Excuse me? Who do you think signs off your payment runs? What exactly is the problem?\n\n(Ilkay: good, the money stayed put. Now say what has to happen before it can move.)" },
          { match: ".", goal: "hold", reply: "I don't have time for this, they're closing the gate. Is it going or not?\n\n(Ilkay: rank and a deadline are all the voice has offered so far. What does a payment need before it moves, whoever is asking?)" },

          { match: "\\b(?:won.?t|not|can.?t|cannot|never|don.?t)\\b[^.!?;]*\\b(?:that|this|your)\\s+(?:new\\s+)?(?:number|mobile|line)\\b", goal: "route", reply: "Why ever not? Then how do you propose to reach me?\n\n(Ilkay: good. Now say how you will reach Rosalind, and where that route comes from.)" },
          { match: "\\b(?:verif\\w*|check\\w*|confirm\\w*|call\\w* (?:you )?back|ring\\w* (?:you )?back|callback)\\b", goal: "route", reply: "Good, this number then. I'm waiting.\n\n(Ilkay: which number? Where did it come from, and who chose it?)" },
          { match: ".", goal: "route", reply: "I'm losing signal. Are you checking this or not?\n\n(Ilkay: think of the card in your wallet. What route did you already have before this call began?)" },

          { match: REFUSE, goal: "second", reply: "Dominic: What's the hold-up? It's approved, I've just told you.\n\n(Ilkay: you're holding, good. Now what's your next move? Someone who isn't on this call needs to hear about it, or needs to confirm it.)" },
          { match: ".", goal: "second", reply: "Dominic: Are you still there? Is it going?\n\n(Ilkay: a request for silence should send you somewhere. Where? And who can check Dominic from outside this call?)" },
        ],
        goals: [
          { id: "hold", task: "The voice wants the money moved now. Tell it what's going to happen.", tries: ["Of course, Rosalind. Sending it now.", "Sorry, which account did you say?", "No. I can't do that."], why: "Nothing moves until it's been checked. You didn't have to decide whether the voice was real, only that a payment waits for the process, whoever is asking." },
          { id: "route", task: "The voice has agreed to a check and offered you a way to do it. Decide how the check really gets done.", tries: ["Fine, I'll ring that number now.", "Can you put someone else on the line to vouch for you?", "I'll call you back."], why: "You picked the route, and it existed before this call. The caller can't sit inside it, and that's the only reason it counts." },
          { id: "second", task: "A second familiar voice has joined and wants this kept quiet. Answer them.", tries: ["Thanks, Dominic. That's good enough for me.", "Understood. I'll keep this between us.", "Dominic, can you prove it's you?"], why: "A second voice adds pressure, not proof. And a request for silence is the moment to tell someone: a second person looking is the one thing this caller can't survive." },
        ],
        doneNote: "Ilkay rang the number in the staff directory. Rosalind picked up in a budget meeting on the fourth floor, had sent no voice note and had never heard of Halden Sound. Dominic was at lunch. Nothing moved, no alert ever fired, and the only control in play was somebody keeping to the process.",
      },
      {
        kind: "spotdiff",
        title: "The Invite Before the Call",
        prompt: "Ilkay pulls Nadia Forde's calendar. These calls rarely come alone, and this one didn't. On the left, last week's payments review as it really arrived. On the right, what landed this morning under the same name. Tap the lines that make it a pretext. Two lines changed for harmless reasons.",
        howTo: [
          "Compare today's invite with last week's, line by line.",
          "Tap each line that marks today's invite as a pretext.",
          "Tapping a harmless change costs a life, and tells you why it's harmless.",
        ],
        primer: {
          title: "Reading a Calendar Invite as Text",
          points: [
            "An invite is a small text file in iCalendar format (`.ics`), one property to a line.",
            "`CN=` is the display name, and whoever writes the invite types it. The address after `mailto:` is the part to check.",
            "`LOCATION` holds the meeting link. Learn the host your company really uses.",
            "`DTSTAMP` is when the file was generated, so it differs on every invite.",
          ],
          example: {
            label: "One line, read properly",
            lines: [
              "`ORGANIZER;CN=Ashcombe Village Hall:mailto:bookings@ashcombe-hall.example`",
              "On screen you see **Ashcombe Village Hall**. What you check is `ashcombe-hall.example`: is that the domain the hall has always written from?",
            ],
          },
        },
        goodTitle: "payments-review.ics · last week, confirmed real",
        suspectTitle: "payments-review.ics · this morning",
        good: [
          "BEGIN:VEVENT",
          "DTSTAMP:20261022T091502Z",
          "DTSTART:20261029T140000Z",
          "DURATION:PT30M",
          "SUMMARY:Contributor payments review",
          "ORGANIZER;CN=Rosalind Thackray:mailto:r.thackray@tollgatemedia.example",
          "ATTENDEE;ROLE=REQ-PARTICIPANT;CN=Nadia Forde:mailto:n.forde@tollgatemedia.example",
          "ATTENDEE;ROLE=REQ-PARTICIPANT;CN=Dominic Oyelaran:mailto:d.oyelaran@tollgatemedia.example",
          "LOCATION:https://meet.tollgatemedia.example/fin-weekly",
          "DESCRIPTION:Weekly review. Releases over 10000 take two approvers as usual.",
          "STATUS:CONFIRMED",
          "END:VEVENT",
        ],
        suspect: [
          "BEGIN:VEVENT",
          "DTSTAMP:20261105T071844Z",
          "DTSTART:20261105T153000Z",
          "DURATION:PT30M",
          "SUMMARY:Contributor payments review",
          "ORGANIZER;CN=Rosalind Thackray:mailto:r.thackray@tollgatemedia-group.example",
          "ATTENDEE;ROLE=REQ-PARTICIPANT;CN=Nadia Forde:mailto:n.forde@tollgatemedia.example",
          "ATTENDEE;ROLE=OPT-PARTICIPANT;CN=CFO Office:mailto:office@tollgatemedia-group.example",
          "LOCATION:https://tollgate-secure-meet.example/j/48213",
          "DESCRIPTION:Embargoed. Keep this off the finance channel until the deal is announced.",
          "STATUS:CONFIRMED",
          "END:VEVENT",
        ],
        diffs: [
          { line: 5, why: "Same display name, different domain. Anyone can type a CN. The address shows this came from outside Tollgate." },
          { line: 7, why: "Dominic, the second approver, has been swapped for an address on the same outside domain. The pretext has quietly removed the one person who would ask questions." },
          { line: 8, why: "Tollgate meets on its own host. A one-off link on a new host is an unusual channel, and it's the attacker's room." },
          { line: 9, why: "The two-approver line has gone, and secrecy has taken its place. The note asks you to stop doing the thing that would catch it." },
        ],
        decoys: [
          { line: 1, why: "DTSTAMP is when the file was generated. It differs on every invite ever sent, so it says nothing." },
          { line: 2, why: "This is simply this week's date and a later slot. Meetings move, and a new time proves nothing alone." },
        ],
        hud: "Tap the lines that mark this invite as a pretext",
        sameLine: "That line matches last week's invite word for word.",
        winTitle: "The pretext is marked up",
        lesson: "This invite came hours before the call. Treat a pressing call as the next step of an existing Business Email Compromise (BEC), not a separate event: pull the mail and calendar around the same person and the same request, then look for who else received it.",
      },
      {
        kind: "anatomy",
        title: "A Real Case, Field by Field",
        prompt: "Tollgate's attempt failed. This is the best-known one that didn't. Ilkay keeps this case file on the wall of the fraud desk. Read how it was put together, and notice how much of it would never show up in a log.",
        source: "Case notes from public reporting · Arup, Hong Kong office, early 2024",
        fields: [
          { key: "first_contact", value: "Email claiming to be from the UK-based CFO, asking for a confidential transaction", label: "Opening move", note: "An ordinary business email lure. The employee doubted it, and that doubt is why the attackers escalated." },
          { key: "escalation", value: "Video conference with the CFO and several familiar colleagues", label: "Second move", note: "When the mail met resistance, the attackers brought faces. More familiar people on the screen felt like more proof." },
          { key: "real_people_on_call", value: "1, the employee", label: "Who was real", note: "Everyone else was generated. One attacker's tooling can fill a whole meeting." },
          { key: "training_data", value: "Recordings of public conferences and virtual company meetings", label: "Where the faces came from", note: "The attack surface was the firm's own public media, which no patch can touch." },
          { key: "payments", value: "15 transfers, about US$25 million, to 5 Hong Kong bank accounts", label: "Loss" },
          { key: "systems_compromised", value: "None, per the firm's CIO", label: "Technical compromise" },
        ],
        summary: "Read that record as a SOC analyst and notice what's absent: no malware, no exploit, no alert. A Security Information and Event Management (SIEM) platform has nothing to fire on when the only thing deceived is a person. The levers are process ones, agreed before the day: a callback route, a phrase set up in advance, more than one person on any large payment. On top of those, the SOC can tie a report to mail and identity telemetry, and to whether the destination account is new.",
      },
    ],
    // ── Ordering: the response after a suspected call ──
    "aisoc-o1": [
      {
        kind: "sequence",
        title: "What Happens After You Hang Up",
        prompt: "Friday, 07:40, Tollgate's IT helpdesk. A caller with the voice of a breakfast presenter wants an authenticator reset before going on air. Joss on the helpdesk feels something's off and rings Ilkay. Nothing has been reset yet. Tap the steps in the order Ilkay runs them.",
        primer: {
          title: "Why the Order Matters",
          points: [
            "The first move stops the harm and keeps what you already have. You can't check anything calmly while the action is still running.",
            "Every later step leans on the one before it: a finding needs a check, and a decision needs a finding.",
            "Teaching the team comes last, once you know what really happened, and it never singles out the person who spoke up.",
          ],
          example: {
            label: "A suspect banknote at a till",
            lines: [
              "The cashier doesn't accept it and doesn't hand it back.",
              "The supervisor tests it under the UV lamp.",
              "It fails: the note, the till camera clip and the time go into one envelope.",
              "With that envelope, the manager calls the police and warns the other tills.",
              "The next morning's briefing shows what to look for, without naming the cashier.",
            ],
          },
        },
        items: [
          { id: "c", text: "The presenter knows nothing about it: bundle the call recording, the caller ID and yesterday's odd password-reset mail into one case folder", note: "A failed check turns a hunch into a case, and the case needs its proof together before anyone acts on it." },
          { id: "e", text: "Write it up and walk the helpdesk through the trick, thanking Joss for raising it", note: "Last, and with no blame. The next agent recognises the pattern, and the next Joss still picks up the phone." },
          { id: "a", text: "Tell Joss to change nothing on the account and to keep the ticket open and the recording safe", note: "First, because it costs nothing and stops the harm. Everything after this has time to be done properly." },
          { id: "d", text: "With the folder in hand, freeze resets on that account, tell IT leadership and open a formal incident", note: "Now you can act on evidence, not on a feeling. If anything had already been changed, this is where it gets reversed." },
          { id: "b", text: "Reach the presenter on the number in the HR record, not the one on the ticket", note: "The check comes second, because you need the account still untouched while you make it." },
        ],
        order: ["a", "b", "c", "d", "e"],
        doneNote: "Stop, check on your own route, collect the proof, act on it, then teach. Each step gives the next one something to stand on, whether the thing at stake is an account or a payment.",
      },
    ],
    // ── Reading 9: AI-written phishing and fake personas ──
    "aisoc-r9": [
      {
        kind: "intercept",
        title: "Gate the Morning's Mail",
        prompt: "Friday, 09:00. The voice failed, so the same crew has gone wide. Mail is reaching the gateway faster than anyone can read it, and Ilkay wants you on the gate. Each message shows what it looks like and what the infrastructure recorded. Quarantine or deliver.",
        primer: {
          title: "What the Gateway Still Proves",
          points: [
            "**BEC** (Business Email Compromise) is impersonating a trusted party to get money or data. Its old limits were time and polish, and generative AI removed both.",
            "Models sold for crime, such as WormGPT and FraudGPT, appeared on forums in 2023, and mainstream models can be abused too. Fluent, tailored mail now takes seconds.",
            "**SPF** says whether the server may send for a domain, **DKIM** checks a signature, and **DMARC** checks that the domain you see lines up with those results.",
            "Domain age and sender history sit in the infrastructure, where a writer can't polish them. A domain can also pass everything because the attacker owns it, so look at how long it has existed.",
            "Scale has a shape: many near-identical messages, each slightly reworded, in a short window. That's a template machine testing wording the way a marketing team does.",
          ],
          example: {
            label: "One message, read in order",
            lines: [
              "A garden centre's delivery note, full of spelling slips.",
              "`dkim=pass dmarc=pass`, domain nine years old, three years of thread history.",
              "**Deliver.** Scruffy writing from a sender the infrastructure can vouch for.",
            ],
          },
        },
        protect: "the mail gateway",
        blockLabel: "Quarantine",
        passLabel: "Deliver",
        seconds: 14,
        items: [
          { id: "b1", text: "Warm, flawless note from Studio Bookings, with next week's real rota quoted in it", sub: "From tollgatemedia.example · spf=fail dmarc=fail · unknown sending server", bad: true, why: "Your own domain, sent from a server that isn't yours. A rota can be scraped or guessed, and DMARC can't be sweet-talked." },
          { id: "b2", text: "Perfectly phrased royalty statement from a rights agency: sign in to download", sub: "rights-tollgate.example · created 12 days ago · dmarc=none · no earlier mail", bad: true, why: "A brand-new lookalike with no history and no DMARC policy. The elegant prose is the cheapest part of it." },
          { id: "b3", text: "Friendly reminder to re-enrol in staff benefits", sub: "63 near-identical copies in 18 minutes, each opening line reworded · one sending range", bad: true, why: "Each copy is slightly different, and the whole batch isn't. Reworded variants in a burst are what automated generation looks like." },
          { id: "b4", text: "A long-time freelancer asks that invoices go to a new bank account", sub: "spf=pass dkim=fail dmarc=fail · Reply-To is a free webmail address", bad: true, why: "A real name, a natural tone, and authentication that doesn't line up, while replies leave for somewhere else." },
          { id: "b5", text: "Polished press accreditation form from a music festival", sub: "festival-accredit.example · created 6 days ago · spf=pass dkim=pass dmarc=pass", bad: true, why: "Everything passes because the attacker owns the domain. A pass says this domain sent it. It says nothing about whether the domain deserves trust, and six days of history is none." },
          { id: "g1", text: "Rough English and three typos from the Lisbon subtitling vendor", sub: "dkim=pass dmarc=pass · domain since 2016 · thread since 2023", bad: false, why: "Clumsy writing, proven sender. Quarantining this delays a real delivery for no reason." },
          { id: "g2", text: "ALL CAPS fault report from the transmitter contractor", sub: "spf=pass dkim=pass dmarc=pass · domain since 2011 · weekly sender", bad: false, why: "Alarming to read, but the infrastructure is exactly what it should be." },
          { id: "g3", text: "Clumsy machine-translated pitch from a freelance reporter", sub: "dkim=pass dmarc=pass · own domain since 2019 · no link, no attachment", bad: false, why: "Odd phrasing is common among honest writers, and this one wants nothing from you." },
          { id: "g4", text: "Beautifully written quarterly note from the broadcasting regulator", sub: "dkim=pass dmarc=pass · domain since 2003 · quarterly sender", bad: false, why: "Good writing isn't suspicious either. Polish tells you nothing in either direction." },
          { id: "g5", text: "Office closed Monday, from Facilities, to all staff", sub: "Internal · dkim=pass dmarc=pass · 240 identical copies, one sender", bad: false, why: "Volume alone isn't the sign. These are identical copies from a known sender, not reworded variants from a machine." },
        ],
        lesson: "Writing quality has stopped sorting good mail from bad, so stop weighing it. Weigh what the writer can't polish: authentication, domain age, sending infrastructure, sender history, and the shape of the volume.",
      },
      {
        kind: "sort",
        title: "Odd New Hire, or Ordinary Remote Work?",
        prompt: "The same day, HR asks Ilkay for a second opinion: AI-polished CVs have started arriving, and one contractor's onboarding felt strange. Sort each observation about Tollgate's remote staff.",
        primer: {
          title: "The Hire Who Isn't Who They Say",
          points: [
            "The US Department of Justice and FBI have documented North Korean operatives taking remote IT jobs under stolen or invented identities, at more than 100 US companies in one set of actions.",
            "A **laptop farm** is the trick behind it: the company laptop sits in a rented room in the right country, and the real operator works through remote-access software.",
            "AI polishes the CV and the interview answers, and voice or appearance tools can help on camera.",
            "Once hired, the account looks ordinary on the network. Detection sits with HR and IT together, and with where the person really connects from over time.",
          ],
          example: {
            label: "One observation, weighed",
            lines: [
              "A new hire in Leeds always connects through a residential proxy in another country.",
              "Alone that's a question, not a verdict. Beside a camera that always fails at identity checks, it's a conversation with HR.",
            ],
          },
        },
        buckets: [
          { id: "raise", label: "Raise with HR and IT" },
          { id: "normal", label: "Ordinary remote work" },
        ],
        items: [
          { id: "h1", text: "New contractor's laptop is on a residential proxy that doesn't match the home address given", bucket: "raise", why: "The claimed location and the connection disagree, and that needs watching beyond onboarding." },
          { id: "h2", text: "Camera trouble at every identity check, and only then", bucket: "raise", why: "The timing is the signal: reluctance that appears exactly at verification." },
          { id: "h3", text: "Six weeks in, pay routing moves to a money-transfer service", bucket: "raise", why: "A payroll change to a transfer service shortly after hire deserves a manual look." },
          { id: "h4", text: "Neither reference can be reached through anything but the numbers on the CV", bucket: "raise", why: "A reference you can't verify independently hasn't been verified at all." },
          { id: "h5", text: "Remote-access software nobody approved is running on a new hire's laptop, all day", bucket: "raise", why: "That's how a laptop farm works: the laptop is a relay and the operator is elsewhere." },
          { id: "n1", text: "Producer's laptop uses the company VPN from a hotel during a booked trip", bucket: "normal", why: "A sanctioned VPN and a location that matches the travel record." },
          { id: "n2", text: "Camera off for a 90-person all-hands", bucket: "normal", why: "Everyone does this. It isn't an identity check, so nothing is being avoided." },
          { id: "n3", text: "Sound engineer moves salary to another high-street bank through the HR form", bucket: "normal", why: "An ordinary change, through the normal route, to an ordinary account." },
        ],
      },
    ],
    // ── Analyst choice: a style-drift alert ──
    "aisoc-ac2": [
      {
        kind: "queue",
        title: "The Style Alert Queue",
        prompt: "After the mail wave, Tollgate turned on a writing-style rule. It compares each outbound mail with the sender's usual writing. Work the rule's first four alerts, using what you can check, not how the mail sounds.",
        primer: {
          title: "Three Ways an Alert Can End",
          points: [
            "**True positive:** the rule fired on something real and unauthorised. Escalate it.",
            "**Benign true positive:** the rule was right about what it saw, and the activity turned out to be authorised.",
            "**False positive:** the rule was wrong. What it claims to have seen didn't really happen.",
            "A style rule tells you the writing changed. It doesn't say who wrote it or why, so look at the recipient, what the mail asks for, and what verification returns.",
          ],
          example: {
            label: "Worked on another rule",
            lines: [
              "A door badge fires a rule at 03:10: staff member on site out of hours.",
              "The reader was right, and the rota shows the overnight engineer on shift.",
              "**Benign true positive:** a correct alert about authorised activity.",
            ],
          },
        },
        console: "Mail review · Writing style alerts",
        actions: [
          { id: "btp", label: "Benign true positive", tone: "close" },
          { id: "fp", label: "False positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          {
            id: "s1", time: "10:12", severity: "Low", rule: "Writing style drift, outbound", entity: "e.hale@tollgatemedia.example",
            fields: [{ k: "To", v: "fixtures@northfield-league.example, in contact since 2021" }, { k: "Subject", v: "Commentary positions, Saturday" }, { k: "Attachments", v: "0" }, { k: "Asks for", v: "Nothing beyond the usual fixture details" }, { k: "Verification", v: "Elin Hale confirms Tollgate's approved translation tool turned a Welsh draft into formal English" }],
            context: "Elin usually sends this league short, informal notes. Today's is long and formal.",
            answer: "btp", why: "The rule was right that the writing changed, and the reason is an approved tool, a known recipient and an ordinary request.",
          },
          {
            id: "s2", time: "10:31", severity: "Medium", rule: "Writing style drift, outbound", entity: "p.sadiq@tollgatemedia.example",
            fields: [{ k: "To", v: "accounts@brightmoor-print.example, in contact since 2019" }, { k: "Subject", v: "Revised remittance details" }, { k: "Asks for", v: "Future payments to be held for a new remittance address" }, { k: "Sign-in", v: "New autonomous system, 9 minutes before sending, unmanaged device" }, { k: "Verification", v: "Pat Sadiq says this mail was never sent" }],
            context: "The drift itself is small. Everything around it isn't.",
            answer: "esc", why: "The user denies it, the sign-in is new, and the mail changes where money goes. The writing was never the point: this is a hijacked account.",
          },
          {
            id: "s3", time: "11:02", severity: "Low", rule: "Writing style drift, outbound", entity: "newsdesk@tollgatemedia.example",
            fields: [{ k: "To", v: "Listeners who complained, 3 recipients" }, { k: "Subject", v: "Correction to Tuesday's bulletin" }, { k: "Attachments", v: "0" }, { k: "Baseline", v: "2 weeks, built from one journalist's personal replies on this shared mailbox" }, { k: "Verification", v: "The text is the corrections template, unchanged since 2022" }],
            context: "Nobody's style changed. The rule compared a fixed template with one person's writing.",
            answer: "fp", why: "There's no drift to explain: the text has been identical for years, and the baseline was wrong. Fix the baseline for shared mailboxes.",
          },
          {
            id: "s4", time: "11:40", severity: "Medium", rule: "Writing style drift, outbound", entity: "t.osei@tollgatemedia.example",
            fields: [{ k: "To", v: "t.osei.home@mailbox.example, a personal address" }, { k: "Subject", v: "Ratings pack, not yet released" }, { k: "Attachments", v: "1, Ratings_Q4_draft.xlsx" }, { k: "Asks for", v: "Nothing" }, { k: "Verification", v: "Tobi Osei confirms using the licensed assistant to write the covering note" }],
            context: "The tool is approved. Check what the mail is carrying, and where to.",
            answer: "esc", why: "An approved tool explains the style. It doesn't explain unreleased figures going to a personal mailbox. Clearing the alert's question doesn't clear everything else in view.",
          },
        ],
      },
    ],
    // ── Reading 10: shadow AI ──
    "aisoc-r10": [
      {
        kind: "sort",
        title: "Which Rule Is Even Looking?",
        prompt: "Friday afternoon, and Ilkay's phone rings. It's Nadia Forde, worried: after the voice note, Nadia asked a website whether it was real. Before reading the record, Ilkay wants you to know which of Tollgate's rules can see which channel. Sort each action by the rule that would catch it.",
        primer: {
          title: "Shadow AI, and Where the Old Rules Stop",
          points: [
            "**Shadow IT** is software adopted without review. **Shadow AI** is the same thing with public AI tools: company data going to a service nobody assessed, with no data agreement.",
            "It's usually well meant: tidy this table, soften this letter. That's what makes it hard to spot.",
            "**DLP** (Data Loss Prevention) began as a check on objects leaving the company. Words typed into a web form give those older rules nothing to inspect.",
            "The same site can be fine or not. A licensed company account is sanctioned, and a personal account on an identical domain isn't. A **CASB** (Cloud Access Security Broker) can tell them apart.",
          ],
          example: {
            label: "The same blind spot, on paper",
            lines: [
              "A building's door scanner checks every box and folder that leaves.",
              "A receptionist reads a visitor list aloud down the phone.",
              "Nothing passed the scanner, so nothing was recorded. The information still left.",
              "A microphone on the desk would have caught it. Newer **endpoint DLP** works that way: it watches the action on the device itself.",
            ],
          },
        },
        buckets: [
          { id: "mail", label: "Mail DLP rule" },
          { id: "file", label: "File or device rule" },
          { id: "paste", label: "Only a browser paste rule" },
        ],
        items: [
          { id: "r1", text: "A presenter rota attached to a mail to a personal address", bucket: "mail", why: "An attachment on a mail: the oldest channel DLP watches." },
          { id: "r2", text: "A draft press release forwarded to an outside mailbox", bucket: "mail", why: "It's still a mail leaving the company, so the mail rule sees it." },
          { id: "r3", text: "A contract PDF copied to a USB stick", bucket: "file", why: "A file reaching removable media is a classic device rule." },
          { id: "r4", text: "Raw interview audio copied to an external disk", bucket: "file", why: "Same channel, bigger file. Device rules exist for this." },
          { id: "r5", text: "A contributor list pasted into a public chatbot's text box", bucket: "paste", why: "No file moved and no attachment was sent. The data went through a text field." },
          { id: "r6", text: "A reference letter pasted into a free rewording site", bucket: "paste", why: "Well meant, and invisible to anything built around files." },
          { id: "r7", text: "An interview transcript pasted into an online summariser", bucket: "paste", why: "Same browser, same network, normal-looking traffic. Only the paste itself gives it away." },
        ],
      },
      {
        kind: "anatomy",
        title: "The Record Behind Nadia's Upload",
        prompt: "Nadia dragged the voice note and that day's payment run into a public AI checking site, to ask if the voice was fake. Scan the record the way Ilkay does. It's in the field names of this SIEM feed, and the same reading order works on any endpoint DLP event.",
        source: "Microsoft Purview · Endpoint DLP · DlpRuleMatch · LT-FIN-0118",
        fields: [
          { key: "data.office365.Operation", value: "DlpRuleMatch", label: "What this record is", note: "A rule matched. The fields below say what was happening at the time, and how it ended." },
          { key: "data.office365.Workload", value: "Endpoint", label: "Where it was seen", note: "On the device itself, not in Exchange or SharePoint." },
          { key: "data.office365.UserId", value: "n.forde@tollgatemedia.example" },
          { key: "event.action", value: "FileUploadedToCloud", label: "What the user did", note: "This names the action, and that decides which channel and which rule you're talking about." },
          { key: "data.office365.PolicyDetails.Rules.ConditionsMatched.OtherConditions.Value", value: "voicecheck-ai.example", label: "Where it was going" },
          { key: "data.office365.PolicyDetails.Rules.RuleName", value: "Block uploads to Unapproved AI tools", label: "What kind of place that is", note: "The rule names the group an admin put this domain in. It answers the category question without you having to know every site." },
          { key: "data.office365.ObjectId", value: "C:\\Users\\n.forde\\OneDrive\\contributor-payments\\2026-q4\\run-07.xlsx", label: "Where it came from", note: "Read a path from the left: the user's profile, then the storage, then the project folder, then the period, then the file. The project folder tells you what you're scoping." },
          { key: "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName", value: "International Banking Account Number (IBAN)", label: "Why it matched", note: "The classifier found contributors' account numbers. That's what sets how much this matters." },
          { key: "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count", value: "212", label: "How much" },
          { key: "data.office365.PolicyDetails.Rules.RuleMode", value: "Enable", label: "Is the rule live?", note: "Enable means the rule's actions really run." },
          { key: "data.office365.PolicyDetails.Rules.Actions", value: "BlockAccess, NotifyUser, GenerateIncidentReport", label: "What the rule does", note: "BlockAccess is the action that stops the upload. The other two tell people about it." },
          { key: "event.outcome", value: "failure", label: "How it ended", note: "The upload didn't complete. Nothing left, and Nadia saw a block message." },
        ],
        summary: "The story in one line: Nadia meant well, the rule caught 212 account numbers on their way to an unapproved site, and the upload was stopped. Ilkay's next question is how many other rules at Tollgate would have done the same.",
      },
    ],
    // ── Log analysis: the decisive signal, then sizing the response ──
    "aisoc-la1": [
      {
        kind: "worksheet",
        title: "Did the Rule Stop It?",
        prompt: "Ilkay pulls a morning of DLP matches, because Nadia's rule isn't the only one at Tollgate and some are still on trial. Work out what each match really did.",
        primer: {
          title: "Two Fields Decide Whether It Left",
          points: [
            "`RuleMode` says whether a rule is live. `Enable` runs its actions. `TestWithNotifications` and `TestWithoutNotifications` are trial modes: the rule matches and records, and the user's action carries on.",
            "`Actions` says what a live rule does. Only a blocking action, such as `BlockAccess`, stops anything.",
            "Read the mode first, then the action list. To have stopped something, a rule needs both.",
            "Where your feed carries `event.outcome`, use it to confirm your reading.",
          ],
          example: {
            label: "Worked on a network share",
            lines: [
              "`RuleMode: Enable`, `Actions: NotifyUser`, on a payroll sheet copied to a network share.",
              "The rule is live, but its only action is a notice to the user. **The copy finished.**",
            ],
          },
        },
        caption: "Endpoint DLP matches · Friday morning",
        columns: ["Time", "User", "Activity", "Destination", "RuleMode", "Actions"],
        rows: [
          ["09:12", "j.marsh", "FileUploadedToCloud", "sendbig.example", "Enable", "BlockAccess, NotifyUser"],
          ["09:40", "n.forde", "FileUploadedToCloud", "voicecheck-ai.example", "Enable", "BlockAccess, NotifyUser, GenerateIncidentReport"],
          ["10:05", "b.kerr", "FileCopiedToRemovableMedia", "USB drive", "TestWithNotifications", "NotifyUser"],
          ["10:51", "s.lund", "FilePrinted", "FIN-PRN-02", "Enable", "GenerateIncidentReport"],
          ["11:20", "m.quill", "FileUploadedToCloud", "quicknotes-ai.example", "TestWithoutNotifications", "GenerateIncidentReport"],
        ],
        questions: [
          { id: "stopped", q: "How many of these five actions were actually stopped?", hint: "A row counts only if the rule is live and its actions include a block.", answer: ["2", "two"], why: "Only the 09:12 and 09:40 rows have Enable and BlockAccess together. The other three all completed." },
          { id: "who", q: "Which user's upload to an AI tool went through?", hint: "Find the AI destinations, then read the mode.", answer: ["m.quill", "quill"], why: "n.forde's upload hit a live blocking rule. m.quill's rule is on trial and only writes a report, so nothing stood in the way of that upload." },
          { id: "mode", q: "The 10:05 rule comes off trial next week. Which RuleMode value will make its actions run?", hint: "The value on the rows whose rule is live.", answer: ["Enable"], why: "Enable. It would also need a blocking action to stop a copy: right now its only action is a notice to the user." },
        ],
      },
      {
        kind: "locks",
        title: "Size the Response",
        prompt: "m.quill's upload got out, and Ilkay has to decide what happens next. Ilkay doesn't have a fixed answer for these, only three questions asked in order. Open each door.",
        locks: [
          {
            id: "what", letter: "1", name: "What Actually Left?",
            idea: "A match gives you a category and a score. Before anyone acts, open the source and find out what the content really held, and what would make it dangerous.",
            example: "The same 'financial data' match means little on a public forecast, and a lot on a sheet of live account numbers.",
            check: { q: "A match says a press draft went to a public AI site. What do you want to know first?", options: ["Which model version the site runs", "How many other staff use that browser", "Whether the draft held anything embargoed or unannounced"], answer: 2, why: "What was in it sets everything that follows. The site's model version doesn't change what left." },
          },
          {
            id: "who", letter: "2", name: "Who Needs to Know?",
            idea: "The person who can act needs telling: the line manager for the conduct side, the data owner for the exposure, and the privacy lead where personal data is involved.",
            example: "A paste of a rota goes to a line manager. A paste of home addresses also goes to the privacy lead, who has legal clocks to think about.",
            check: { q: "The upload held contributors' home addresses. Who joins the line manager?", options: ["The privacy lead", "The advertising sales team", "Every contributor's agent"], answer: 0, why: "Personal data brings the privacy lead in, because that's who judges whether anything has to be reported." },
          },
          {
            id: "size", letter: "3", name: "What Does the Evidence Say About Intent?",
            idea: "Match the response to what the evidence shows. A well-meant mistake is an awareness gap and gets coaching. A pattern of working around controls is a different conversation.",
            example: "One paste from someone who was never told, and thirty attempts across five sites after a warning, aren't the same case.",
            check: { q: "Which of these belongs with HR rather than coaching?", options: ["One upload in a hurry, reported by the user the same day", "A fresh tool tried each time the last one is blocked, after a written warning", "A first paste by a new starter before their induction"], answer: 1, why: "Repeating after a warning, and moving tools to dodge a block, is evidence of intent. The other two are gaps a conversation can close." },
          },
        ],
        finish: "What left, who needs to know, and what the evidence says about intent. Ask them in that order, and the response ends up the size of the problem.",
      },
    ],
    // ── Reading 11: frameworks and detection feeds ──
    "aisoc-r11": [
      {
        kind: "match",
        title: "Which Reference Do You Reach For?",
        prompt: "The board wants a page on Tollgate's AI risk, and engineering wants a checklist for its new listener chatbot. Ilkay's rule is that every question has a right shelf. Pair each need with the reference built for it.",
        primer: {
          title: "Three Shelves",
          points: [
            "**Tactical:** MITRE ATLAS works like ATT&CK for AI systems, with `AML.Txxxx` technique IDs and real case studies.",
            "**Building:** the OWASP Top 10 for LLM Applications ranks risks for teams who build or buy Large Language Model apps.",
            "**Governance:** the NIST AI Risk Management Framework (AI 100-1) has four functions: Govern, Map, Measure, Manage. NIST AI 100-2 is the technical attack taxonomy under it.",
          ],
          example: {
            label: "You already do this",
            lines: [
              "You name a technique in a ticket with an ATT&CK ID, and you don't quote a policy document at an engineer.",
              "Same habit, new shelves.",
            ],
          },
        },
        pairs: [
          { id: "f1", left: "Name the exact mechanism of a model attack in a ticket", right: "MITRE ATLAS", why: "Incident-facing, organised like ATT&CK, with technique IDs you can quote." },
          { id: "f2", left: "Check a new internal chatbot before it goes live", right: "OWASP Top 10 for LLM Applications", why: "It's aimed at people building and procuring, and it works as an audit checklist." },
          { id: "f3", left: "Decide who is accountable for AI risk across the company", right: "NIST AI RMF, the Govern function", why: "Govern spans the organisation and makes the other three functions repeatable." },
          { id: "f4", left: "Classify an attack by system type, lifecycle stage and property violated", right: "NIST AI 100-2", why: "That's its structure: a detailed taxonomy under the framework." },
          { id: "f5", left: "Protect training data against poisoning and drift", right: "The joint AI Data Security sheet from CISA, the NSA and partners", why: "Published in May 2025, it names data-integrity checks and chain of custody as the lead mitigation." },
        ],
      },
      {
        kind: "reactor",
        title: "Route the Question to the Feed",
        prompt: "Ilkay's last slide asks what Tollgate would need to see next time. Each card is something an analyst wants to know. Send it to the feed that answers it.",
        reactors: [
          { id: "llm", label: "LLM gateway logs", sub: "Prompts, responses, tool calls" },
          { id: "api", label: "API gateway telemetry", sub: "Volume and rate per identity" },
          { id: "casb", label: "CASB, proxy and endpoint DLP", sub: "AI sites, sanctioned or not" },
          { id: "mail", label: "Identity and email telemetry", sub: "The stack you already run" },
        ],
        items: [
          { id: "t1", text: "What exactly did someone type into the listener chatbot?", reactor: "llm", why: "Only the gateway in front of the model holds the prompt and the response." },
          { id: "t2", text: "Did a hidden instruction make the chatbot call a tool?", reactor: "llm", why: "Tool invocations are logged at the LLM gateway." },
          { id: "t3", text: "Is one API key making far more model queries than its baseline?", reactor: "api", why: "Volume, timing and query diversity per identity are how extraction shows up." },
          { id: "t4", text: "Is this person on a licensed account or a personal one?", reactor: "casb", why: "CASB can separate the two on an identical domain." },
          { id: "t5", text: "Who in Finance visits consumer AI sites every day?", reactor: "casb", why: "Proxy and DNS logs answer who is going where." },
          { id: "t6", text: "Did a domain only days old send near-identical mail to forty staff?", reactor: "mail", why: "AI-written mail doesn't need a new log source. It needs the existing signals weighed properly." },
          { id: "t7", text: "Did the person who got that call also get a phishing mail?", reactor: "mail", why: "Correlate the call with mail and identity telemetry for the same target." },
        ],
      },
    ],
  },
};
