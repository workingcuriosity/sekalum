const required = ['UI_LIVE_BASE_URL', 'UI_LIVE_ADMIN_TOKEN', 'UI_LIVE_CONSUMER_TOKEN'];
const missing = required.filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.log(JSON.stringify({ classification: 'SKIPPED_WITH_REASON', reason: 'AUTHENTICATED LIVE TEST DATA REQUIRED', missing }, null, 2));
  process.exit(0);
}
console.log(JSON.stringify({ classification: 'SKIPPED_WITH_REASON', reason: 'Live runner requires an approved redacted evidence sink before authenticated execution.' }, null, 2));
