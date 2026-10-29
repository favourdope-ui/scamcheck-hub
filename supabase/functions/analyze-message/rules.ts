// Transparent heuristic rules for ScamCheck Hub. These are warning signals, not a verdict.
export function analyzeMessage(raw: string) {
  const text = raw.toLowerCase();
  let score = 0;
  const findings: { title: string; detail: string; points: number }[] = [];
  const rules = [
    { points: 24, regex: /\b(urgent|immediately|act now|within \d+ hours?|final warning|account will be (?:closed|suspended|blocked))\b/i, title: "Urgency or threat", detail: "Pressure to act quickly can stop you from checking whether a request is genuine." },
    { points: 30, regex: /\b(password|one[- ]time (?:password|code|passcode)|verification code|recovery phrase|seed phrase|pin number)\b/i, title: "Sensitive information requested", detail: "Do not disclose passwords, one-time codes, or wallet recovery phrases." },
    { points: 26, regex: /\b(send|pay|transfer|deposit|wire|release fee|processing fee|activation fee)\b.{0,65}\b(money|payment|cash|fee|bitcoin|btc|crypto|usdt|gift card|wallet|account)\b|\b(money|payment|fee|bitcoin|btc|crypto|usdt|gift card)\b.{0,55}\b(send|pay|transfer|deposit|release|claim)\b/i, title: "Payment or advance-fee pressure", detail: "Verify independently before paying an upfront fee or sending money, especially by crypto or gift card." },
    { points: 20, regex: /\b(prize|lottery|you have won|winner|free gift|giveaway|claim your reward|inheritance)\b/i, title: "Unexpected prize or reward", detail: "Unexpected winnings can be used to solicit fake fees or personal details." },
    { points: 18, regex: /\b(guaranteed profit|risk[- ]free investment|double your money|100% return|sure win|investment opportunity)\b/i, title: "Unrealistic financial promise", detail: "High returns cannot be guaranteed without risk." },
    { points: 15, regex: /\b(keep (?:this|it) secret|don't tell anyone|do not tell anyone|act before anyone finds out)\b/i, title: "Secrecy pressure", detail: "A demand for secrecy can be used to isolate you from trusted advice." },
    { points: 12, regex: /\b(click (?:this|the) link|verify your account|login here|confirm your account|update your payment)\b/i, title: "Link or account-verification prompt", detail: "Avoid signing in through unsolicited links; visit the official site or app directly." },
    { points: 12, regex: /\b(remote access|install (?:this )?app|anydesk|teamviewer)\b/i, title: "Remote access request", detail: "Unexpected remote-access requests can give a stranger control of your device." },
  ];
  for (const rule of rules) {
    if (rule.regex.test(text)) {
      score += rule.points;
      findings.push({ title: rule.title, detail: rule.detail, points: rule.points });
    }
  }
  const urlCount = (raw.match(/https?:\/\/|www\./gi) || []).length;
  if (urlCount) {
    const points = Math.min(12, urlCount * 6);
    score += points;
    findings.push({ title: "Link included", detail: "A link alone does not prove a scam; inspect the domain and avoid signing in from unsolicited messages.", points });
  }
  score = Math.min(100, score);
  const level = score >= 55 ? "High" : score >= 25 ? "Elevated" : "Lower";
  if (!findings.length) {
    findings.push({ title: "No common warning pattern detected", detail: "This check did not match its known rules. Scams can look normal, so verify the sender and request independently.", points: 0 });
  }
  return { score, level, findings, method: "server-side-rule-based", version: 1, checkedAt: new Date().toISOString() };
}
