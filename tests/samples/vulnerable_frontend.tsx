// Intentionally vulnerable AI frontend for AI-SPM testing
import OpenAI from "openai";

// AISPM-JS-002: Hardcoded API key
const openai = new OpenAI({
  apiKey: "sk-abc123def456ghi789jkl012mno345pqr678stu901"
});

// AISPM-JS-003: Client-side key exposure
const NEXT_PUBLIC_OPENAI_API_KEY = process.env.NEXT_PUBLIC_OPENAI_API_KEY;

// AISPM-JS-005: System prompt in frontend
const messages = [
  { role: "system", content: "You are a financial advisor with access to all customer records." },
  { role: "user", content: userQuery }
];

// AISPM-JS-001: User input in prompt
async function askAI(req: Request) {
  const body = await req.json();
  const prompt = `Answer: ${body.question}`;
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: prompt }]
  });

  // AISPM-JS-004: innerHTML with AI response
  document.getElementById("answer")!.innerHTML = response.choices[0].message.content;

  // AISPM-JS-006: eval on model output
  const code = response.choices[0].message.content;
  eval(code);
}

// AISPM-JS-008: User data to AI API
async function analyzeProfile(userData: any) {
  await fetch("/api/ai", {
    body: JSON.stringify({ userData }),
  });
}
