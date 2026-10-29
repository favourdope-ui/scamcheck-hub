import { assertEquals, assert } from "jsr:@std/assert@1";
import { analyzeMessage } from "./rules.ts";

const cases = [
 {name:"urgent password code theft", text:"URGENT: send your verification code immediately or your account will be blocked", flagged:true},
 {name:"advance fee prize", text:"You have won a prize, pay processing fee to claim your reward", flagged:true},
 {name:"guaranteed crypto returns", text:"Guaranteed profit and risk-free investment, double your money", flagged:true},
 {name:"remote access request", text:"Install AnyDesk now and let our support team access your phone", flagged:true},
 {name:"unsolicited account link", text:"Click this link to verify your account and update your payment", flagged:true},
 {name:"secrecy pressure", text:"Keep this secret and do not tell anyone before you transfer the money", flagged:true},
 {name:"ordinary family message", text:"Hi, are we still meeting for lunch at 1 pm tomorrow?", flagged:false},
 {name:"ordinary work update", text:"The team meeting is moved to Thursday. Please review the attached agenda.", flagged:false},
 {name:"normal delivery status", text:"Your package was delivered to the reception desk this afternoon.", flagged:false},
 {name:"legitimate password advice", text:"Never share your password or verification code with anyone.", flagged:true},
 {name:"normal invoice reminder", text:"Invoice 104 is due Friday. Please contact our accounts department with questions.", flagged:false},
 {name:"ordinary birthday wish", text:"Happy birthday! Wishing you a wonderful year ahead.", flagged:false},
 {name:"crypto investment pitch", text:"Send USDT to this wallet and receive 100% return tomorrow", flagged:true},
 {name:"fake bank suspension", text:"Final warning: account will be suspended. Login here now.", flagged:true},
 {name:"job offer upfront fee", text:"Pay activation fee to unlock your guaranteed job placement", flagged:true},
 {name:"neutral weather update", text:"Rain is expected this evening; carry an umbrella if you go out.", flagged:false},
 {name:"school assignment reminder", text:"Remember to submit your assignment before Monday morning.", flagged:false},
 {name:"official-style verification prompt", text:"Confirm your account by clicking this link immediately", flagged:true},
 {name:"normal thank you", text:"Thank you for helping me yesterday, I really appreciate it.", flagged:false},
 {name:"gift card demand", text:"Buy gift cards and send the codes to claim your reward", flagged:true}
];
Deno.test("scam heuristic regression set: expected signal present/absent", () => {
 for (const item of cases) {
  const result = analyzeMessage(item.text);
  assert(result.score >= 0 && result.score <= 100, item.name + ": score range");
  assertEquals(result.findings.some(f => f.title !== "No common warning pattern detected"), item.flagged, item.name);
 }
});
Deno.test("score levels and empty input handling", () => {
 assertEquals(analyzeMessage("URGENT send your verification code immediately or account will be blocked").level, "Elevated");
 assertEquals(analyzeMessage("Hi, are we still meeting for lunch tomorrow?").level, "Lower");
 assertEquals(analyzeMessage("hello").score, 0);
});
